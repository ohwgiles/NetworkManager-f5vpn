/*
 * NetworkManager-f5vpn
 * Plugin for NetworkManager to access F5 Firepass SSL VPNs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */
#include "f5vpn_connect.h"
#include "glib_curl.h"
#include "pppd-plugin-message.h"
#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <glib-unix.h>
#include <libxml/xpath.h>
#include <pty.h>
#include <stdio.h>
#include <unistd.h>

G_DEFINE_QUARK (f5vpn - connect - error - quark, f5vpn_connect_error)
#define F5VPN_CONNECT_ERROR f5vpn_connect_error_quark ()

#ifdef WITH_DEBUG
#define debug(...) fprintf (stderr, __VA_ARGS__)
#else
#define debug(...) (void) 0
#endif

#define _STR(x)          #x
#define STR(x)           _STR (x)
#define PPPD_PLUGIN_PATH STR (PPPD_PLUGIN)

struct _F5VpnConnection
{
	GlibCurl *glc;
	F5VpnConnectCallback callback;
	void *userdata;
	GError *err;
	GString *resp;
	gchar *session_key;
	int ssl_write_fd;
	int ppd_fd;
	GSList *parsed_lans;
	GSList *parsed_nameservers;
	pid_t ppd_pid;
	pid_t openssl_pid;
};

void
tunnel_exited (F5VpnConnection *vpn)
{
	/* TODO: if due to an error condition, report via GError */
	(*vpn->callback) (vpn, NULL, vpn->userdata, NULL);
}

void
tunnel_up (F5VpnConnection *vpn, const NetworkSettings *settings)
{
	(*vpn->callback) (vpn, settings, vpn->userdata, NULL);
}

static gboolean
handle_plugin_msg (gint fd, GIOCondition condition, gpointer user)
{
	(void) condition;

	PppdPluginNotification msg;
	long n = read (fd, &msg, sizeof (PppdPluginNotification));
	g_assert_true (n == sizeof (PppdPluginNotification));
	msg.ifname[sizeof (msg.ifname) - 1] = '\0';

	char local_addr[INET_ADDRSTRLEN], remote_addr[INET_ADDRSTRLEN];
	inet_ntop (AF_INET, &msg.local_addr, local_addr, INET_ADDRSTRLEN);
	inet_ntop (AF_INET, &msg.remote_addr, remote_addr, INET_ADDRSTRLEN);

	debug ("plugin notified: local %s remote %s ifname %s\n", local_addr, remote_addr, msg.ifname);

	F5VpnConnection *vpn = (F5VpnConnection *) user;

	NetworkSettings settings;
	settings.local_ip = msg.local_addr.s_addr;
	settings.remote_ip = msg.remote_addr.s_addr;
	settings.lans = vpn->parsed_lans;
	settings.nameservers = vpn->parsed_nameservers;
	strcpy (settings.device, msg.ifname);

	tunnel_up (vpn, &settings);

	return G_SOURCE_CONTINUE;
}

static gboolean
fallback_read_write_fds (gint fd, GIOCondition condition, gpointer user)
{
	if (condition & G_IO_HUP)
		return debug ("hup on %d\n", fd), G_SOURCE_REMOVE;

	int out_fd = (intptr_t) user;
	char buf[4096];

	long buflen = read (fd, buf, 4096);
	if (buflen < 0) {
		debug ("fallback_read_write_fds read failed: %s\n", strerror (errno));
		return G_SOURCE_REMOVE;
	}

	long nwrote = 0;
	char *bufp = buf;
	while (nwrote < buflen) {
		nwrote = write (out_fd, bufp, buflen);
		if (nwrote < 0) {
			if (errno == EAGAIN) {
				sched_yield ();
				continue;
			}
			fprintf (stderr, "fallback_read_write_fds: write() on %d returned %ld: %s\n", out_fd, nwrote, strerror (errno));
			return G_SOURCE_REMOVE;
		}
		buflen -= nwrote;
		bufp += nwrote;
	}

	return G_SOURCE_CONTINUE;
}

static gboolean
splice_fds (gint fd, GIOCondition condition, gpointer user);

static gboolean
splice_write_ready (gint fd, GIOCondition condition, gpointer user)
{
	(void) condition;

	int from_fd = (intptr_t) user;
	long n = splice (from_fd, NULL, fd, NULL, 4096, SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
	if (n < 0) {
		fprintf (stderr, "splice_write_ready: splice() returned %ld: %s\n", n, strerror (errno));
	}

	// Add the read handler back
	g_unix_fd_add (from_fd, G_IO_IN, splice_fds, (gpointer) (intptr_t) fd);

	return G_SOURCE_REMOVE;
}

static gboolean
splice_fds (gint fd, GIOCondition condition, gpointer user)
{
	if (condition & G_IO_HUP)
		return debug ("hup on %d\n", fd), G_SOURCE_REMOVE;

	int out_fd = (intptr_t) user;
	long n = splice (fd, NULL, out_fd, NULL, 4096, SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
	if (n < 0) {
		if (errno == EINVAL) {
			// Some kernels do not support splice() between a pipe and a tty
			debug ("splice from %d to %d returned EINVAL, replacing handler with fallback using read/write\n", fd, out_fd);
			g_unix_fd_add (fd, G_IO_IN, fallback_read_write_fds, (gpointer) (intptr_t) out_fd);
		} else if (errno == EAGAIN) {
			// Wait until the other side is ready to write
			g_unix_fd_add (out_fd, G_IO_OUT, splice_write_ready, (gpointer) (intptr_t) fd);
		} else {
			fprintf (stderr, "splice_fds: splice() returned %ld: %s\n", n, strerror (errno));
		}
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

static void
setnonblocking (int fd)
{
	fcntl (fd, F_SETFL, fcntl (fd, F_GETFL, 0) | O_NONBLOCK);
}

/* Forks and execs pppd. PPP is full-duplex, but instead of using stdin/stdout
 * pipes, it uses a pty. This is for irrelevant/legacy reasons such has modem
 * hardware flow control. The upshot is that this function returns a
 * bidirectional file descriptor, data_fd. It also returns two regular pipes for
 * polling, plugin_fd and log_fd, which allow receiving messages from the ppp
 * plugin and reading pppd log messages respectively */
static int
launch_pppd (const char *pppd_ip_spec, int *data_fd, int *plugin_fd, int *log_fd)
{
#ifndef WITH_DEBUG
	(void) log_fd;
#endif

	int ret, pty_master, pty_slave, pipe_plugin[2];
	char fd_as_str[3];

	if (pipe (pipe_plugin) == -1)
		return -1;

	openpty (&pty_master, &pty_slave, NULL, NULL, NULL);

#ifdef WITH_DEBUG
	int pipe_log[2];
	if (pipe (pipe_log) == -1)
		return -1;
#endif

	ret = fork ();
	if (ret == -1) {
		fprintf (stderr, "fork failed: %s\n", strerror (errno));
		return -1;
	} else if (ret == 0) {
		/* child process: fork pppd */
		close (pipe_plugin[0]);
		sprintf (fd_as_str, "%d", pipe_plugin[1]);

		setenv ("F5_VPN_PPPD_PLUGIN_FD", fd_as_str, 1);
		close (pty_master);
		dup2 (pty_slave, STDIN_FILENO);
		close (pty_slave);

		close (STDOUT_FILENO);
		close (STDERR_FILENO);

#ifdef WITH_DEBUG
		close (pipe_log[0]);
		sprintf (fd_as_str, "%d", pipe_log[1]);
#endif
		execl ("/usr/bin/pppd", "/usr/bin/pppd", "local", "nodetach", "noauth",
		       "nocrtscts", "nodefaultroute", "noremoteip", "noproxyarp", "plugin",
		       PPPD_PLUGIN_PATH, pppd_ip_spec,
#ifdef WITH_DEBUG
		       "logfd", fd_as_str, "debug",
#endif
		       NULL);
		exit (EXIT_FAILURE);
	} else {
		/* parent process: clean up fds and pass them back up */
		close (pty_slave);
		setnonblocking (pty_master);
		*data_fd = pty_master;
		*plugin_fd = pipe_plugin[0];
#ifdef WITH_DEBUG
		close (pipe_log[1]);
		*log_fd = pipe_log[0];
#endif
		return ret;
	}
}

static void
pppd_exited (GPid pid, gint status, gpointer user_data)
{
	F5VpnConnection *vpn = (F5VpnConnection *) user_data;
	if (WIFEXITED (status)) {
		debug ("pppd exited with status %d\n", WEXITSTATUS (status));
	} else {
		debug ("pppd unexpectedly stopped\n");
	}
	g_assert (vpn->ppd_pid == pid);
	vpn->ppd_pid = 0;
	if (vpn->openssl_pid)
		kill (vpn->openssl_pid, SIGTERM);
	else
		tunnel_exited (vpn);
}

static void
openssl_exited (GPid pid, gint status, gpointer user_data)
{
	F5VpnConnection *vpn = (F5VpnConnection *) user_data;
	if (WIFEXITED (status)) {
		debug ("openssl exited with status %d\n", WEXITSTATUS (status));
	} else {
		debug ("openssl unexpectedly stopped\n");
	}
	g_assert (vpn->openssl_pid == pid);
	vpn->openssl_pid = 0;
	if (vpn->ppd_pid)
		kill (vpn->ppd_pid, SIGTERM);
	else
		tunnel_exited (vpn);
}

static gboolean
on_ssl_established (gint fd, GIOCondition condition, gpointer user)
{
	(void) condition;

	char *p, *e;
	F5VpnConnection *vpn = (F5VpnConnection *) user;
	// We expect an HTTP response like this:
	//   HTTP/1.0 200 OK
	//   Content-length: 0
	//   X-VPN-client-IP: 192.168.1.6
	//   X-VPN-server-IP: 1.1.1.1

	char buffer[128];
	int n = 0;
	/* Look for the \r\n\r\n signifying the end of the HTTP header. This is a very
   * inefficent loop, but reading bigger chunks risks going over the header and
   * into the PPP data; doing something smarter isn't worth the effort */
	do
		if (read (fd, buffer + n, 1) == 1)
			n++;
	while (errno == 0 && (n < 4 || memcmp (buffer + n - 4, "\r\n\r\n", 4)));
	buffer[n] = '\0';
	// debug("received %d bytes [%s]\n", n, buffer);
	// debug("last 4 bytes [%x %x %x %x]\n", buffer[n-4], buffer[n-3],
	// buffer[n-2], buffer[n-1]);

	/* TODO: no way to return error from this func */

	char ip_spec[32];
	char *server_ip;
	// Try to extract the client and server IP from the HTTP response header. If
	// it fails, use dummy defaults and hope that IPCP will sort it out for us.
	server_ip = ip_spec + sprintf (ip_spec, "0.0.0.0:");
	if ((p = strstr (buffer, "X-VPN-client-IP: "))) {
		p += strlen ("X-VPN-client-IP: ");
		if ((e = memchr (p, '\r', 16))) {
			*e = '\0';
			server_ip = ip_spec + sprintf (ip_spec, "%s:", p);
		}
	}
	sprintf (server_ip, "1.1.1.1");
	if ((p = strstr (buffer, "X-VPN-server-IP: "))) {
		p += strlen ("X-VPN-server-IP: ");
		if ((e = memchr (p, '\r', 16))) {
			*e = '\0';
			sprintf (server_ip, "%s", p);
		}
	}

	debug ("PPP IP spec: [%s]\n", ip_spec);

	// Pass execution off to pppd
	int ppd_fd;
	int ppd_log;
	int plugin_fd;
	int pppd_pid = launch_pppd (ip_spec, &ppd_fd, &plugin_fd, &ppd_log);
	g_child_watch_add (pppd_pid, pppd_exited, vpn);
	vpn->ppd_pid = pppd_pid;
	vpn->ppd_fd = ppd_fd;
	g_unix_fd_add (plugin_fd, G_IO_IN, handle_plugin_msg, vpn);
#ifdef WITH_DEBUG
	g_unix_fd_add (ppd_log, G_IO_IN, splice_fds, (gpointer) STDERR_FILENO);
#endif
	g_unix_fd_add (ppd_fd, G_IO_IN, splice_fds, (gpointer) (intptr_t) vpn->ssl_write_fd);
	g_unix_fd_add (fd, G_IO_IN, splice_fds, (gpointer) (intptr_t) vpn->ppd_fd);

	// Finished with this handler
	return FALSE;
}

static int
launch_ssl_client (const char *endpoint, int fds[2])
{
	int ret, to_child[2], from_child[2];

	if (pipe (to_child) == -1)
		return -1;

	if (pipe (from_child) == -1)
		return -1;

	ret = fork ();
	if (ret == -1)
		return -1;

	if (ret == 0) {
		close (to_child[1]);
		close (from_child[0]);
		dup2 (to_child[0], STDIN_FILENO);
		close (to_child[0]);
		dup2 (from_child[1], STDOUT_FILENO);
		close (from_child[1]);
		execl ("/usr/bin/openssl", "/usr/bin/openssl", "s_client", "-quiet",
		       "-verify_quiet", "-verify_return_error", "-connect", endpoint, NULL);
		exit (EXIT_FAILURE);
	} else {
		close (to_child[0]);
		close (from_child[1]);
		fds[0] = from_child[0];
		fds[1] = to_child[1];
		setnonblocking (fds[0]);
		setnonblocking (fds[1]);
	}
	return ret;
}

static gboolean
parse_network_settings (F5VpnConnection *vpn, char *lan_segment, char *nameservers)
{
	char *addr, *subnet, *savep;
	struct in_addr bin_addr, bin_subnet;
	for (;;) {
		addr = strtok_r (lan_segment, " ", &savep);
		if (!addr)
			break;
		lan_segment = NULL;
		subnet = strchr (addr, '/');
		if (!subnet)
			break;
		*subnet++ = '\0';
		if (inet_pton (AF_INET, addr, &bin_addr) != 1 || inet_pton (AF_INET, subnet, &bin_subnet) != 1)
			continue;
		LanAddr *la = malloc (sizeof (LanAddr));
		la->addr = bin_addr;
		la->mask = (32 - (uint8_t) __builtin_ctz (ntohl (bin_subnet.s_addr)));
		vpn->parsed_lans = g_slist_append (vpn->parsed_lans, la);
	}

	for (;;) {
		addr = strtok_r (nameservers, " ", &savep);
		if (!addr)
			break;
		nameservers = NULL;

		if (inet_pton (AF_INET, addr, &bin_addr) != 1)
			continue;

		struct in_addr *ns = malloc (sizeof (struct in_addr));
		*ns = bin_addr;

		vpn->parsed_nameservers = g_slist_append (vpn->parsed_nameservers, ns);
	}

	return TRUE;
}

static gboolean
callback_to_user (gpointer user)
{
	F5VpnConnection *vpn = (F5VpnConnection *) user;
	(vpn->callback) (vpn, NULL, vpn->userdata, vpn->err);
	return G_SOURCE_REMOVE;
}

static void
handle_connection_parameters (CURL *curl, void *user, GError *err)
{
	F5VpnConnection *vpn = (F5VpnConnection *) user;
	long response_code = 0;

	xmlDoc *doc;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;

	gchar *ur_Z = NULL, *tunnel_host0 = NULL, *tunnel_port0 = NULL, *DNS0 = NULL,
	      *LAN0 = NULL;

	if (err) {
		curl_easy_cleanup (curl);
		vpn->err = err;
		g_timeout_add (0, callback_to_user, vpn);
		return;
	}

	curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response_code);
	if (response_code != 200) {
		char *url;
		curl_easy_getinfo (curl, CURLINFO_EFFECTIVE_URL, &url);
		vpn->err =
		    g_error_new (F5VPN_CONNECT_ERROR, F5VPN_CONNECT_ERROR_BAD_HTTP_CODE,
		                 "Unexpected HTTP response code %lu received from %s",
		                 response_code, url);
		curl_easy_cleanup (curl);
		g_timeout_add (0, callback_to_user, vpn);
		return;
	}

	curl_easy_cleanup (curl);

	// debug("xml resp: %s\n", vpn->resp->str);

	doc = xmlParseMemory (vpn->resp->str, vpn->resp->len);
	if (doc == NULL) {
		err = g_error_new (F5VPN_CONNECT_ERROR, F5VPN_CONNECT_ERROR_PARSE_FAILED, "Could not parse server response XML: %s", vpn->resp->str);
		(vpn->callback) (vpn, NULL, vpn->userdata, err);
		return;
	}

	xpathCtx = xmlXPathNewContext (doc);

	xpathObj = xmlXPathEvalExpression ((const xmlChar *) "string(/favorite/object/ur_Z)", xpathCtx);
	if (xpathObj && xpathObj->stringval)
		ur_Z = g_strdup ((const gchar *) xpathObj->stringval);
	xmlXPathFreeObject (xpathObj);

	xpathObj = xmlXPathEvalExpression ((const xmlChar *) "string(/favorite/object/tunnel_host0)", xpathCtx);
	if (xpathObj && xpathObj->stringval)
		tunnel_host0 = g_strdup ((const gchar *) xpathObj->stringval);
	xmlXPathFreeObject (xpathObj);

	xpathObj = xmlXPathEvalExpression ((const xmlChar *) "string(/favorite/object/tunnel_port0)", xpathCtx);
	if (xpathObj && xpathObj->stringval)
		tunnel_port0 = g_strdup ((const gchar *) xpathObj->stringval);
	xmlXPathFreeObject (xpathObj);

	xpathObj = xmlXPathEvalExpression ((const xmlChar *) "string(/favorite/object/DNS0)", xpathCtx);
	if (xpathObj && xpathObj->stringval)
		DNS0 = g_strdup ((const gchar *) xpathObj->stringval);
	xmlXPathFreeObject (xpathObj);

	xpathObj = xmlXPathEvalExpression ((const xmlChar *) "string(/favorite/object/LAN0)", xpathCtx);
	if (xpathObj && xpathObj->stringval)
		LAN0 = g_strdup ((const gchar *) xpathObj->stringval);
	xmlXPathFreeObject (xpathObj);

	debug ("ur_Z[%s] tunnel_host0[%s] tunnel_port0[%s] DNS0[%s] LAN0[%s]\n", ur_Z, tunnel_host0, tunnel_port0, DNS0, LAN0);

	xmlXPathFreeContext (xpathCtx);
	xmlFreeDoc (doc);

	if (!(ur_Z && tunnel_host0 && tunnel_port0 && DNS0 && LAN0)) {
		g_free (ur_Z);
		g_free (tunnel_host0);
		g_free (tunnel_port0);
		g_free (DNS0);
		g_free (LAN0);
		vpn->err = g_error_new (F5VPN_CONNECT_ERROR, F5VPN_CONNECT_ERROR_PARSE_FAILED, "Missing expected params in server response XML: %s", vpn->resp->str);
		g_timeout_add (0, callback_to_user, vpn);
		return;
	}

	gchar *ssl_endpoint =
	    g_strdup_printf ("%s:%d", tunnel_host0, atoi (tunnel_port0));
	/* Totally bizarre, but the session string has to be terminated with a newline!? */
	gchar *vpn_http_get = g_strdup_printf (
	    "GET /myvpn?sess=%s\n&hdlc_framing=no&ipv4=yes&ipv6=yes&Z=%s HTTP/1.0\r\n"
	    "User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0; F5 Networks Client)\r\n"
	    "Host: %s\r\n\r\n",
	    vpn->session_key, ur_Z, tunnel_host0);
	free (tunnel_host0);
	free (tunnel_port0);
	free (ur_Z);

	if (!parse_network_settings (vpn, LAN0, DNS0)) {
		free (LAN0);
		free (DNS0);
		vpn->err = g_error_new (F5VPN_CONNECT_ERROR, F5VPN_CONNECT_ERROR_PARSE_FAILED, "Failed to parse LAN0[%s] or DNS0[%s]", LAN0, DNS0);
		g_timeout_add (0, callback_to_user, vpn);
		return;
	}

	free (LAN0);
	free (DNS0);

	int ssl_client_fds[2];
	int openssl_pid = launch_ssl_client (ssl_endpoint, ssl_client_fds);
	g_free (ssl_endpoint);
	g_child_watch_add (openssl_pid, openssl_exited, vpn);
	vpn->openssl_pid = openssl_pid;

	debug ("request [%s]\n", vpn_http_get);

	if (write (ssl_client_fds[1], vpn_http_get, strlen (vpn_http_get)) == -1) {
		g_free (vpn_http_get);
		vpn->err = g_error_new (F5VPN_CONNECT_ERROR, F5VPN_CONNECT_ERROR_PARSE_FAILED, "Failed to write initial HTTP request: %s", strerror (errno));
		g_timeout_add (0, callback_to_user, vpn);
		return;
	}

	g_free (vpn_http_get);
	vpn->ssl_write_fd = ssl_client_fds[1];
	g_unix_fd_add (ssl_client_fds[0], G_IO_IN, on_ssl_established, vpn);
}

F5VpnConnection *
f5vpn_connect (GMainContext *main_context, const char *hostname, const char *session_key, const char *vpn_z_id, F5VpnConnectCallback callback, void *userdata)
{
	F5VpnConnection *vpn = calloc (1, sizeof (F5VpnConnection));

	vpn->glc = glib_curl_new (main_context);
	vpn->resp = g_string_new ("");
	vpn->callback = callback;
	vpn->userdata = userdata;
	vpn->session_key = strdup (session_key);
	vpn->parsed_lans = NULL;
	vpn->parsed_nameservers = NULL;
	vpn->ppd_fd = 0;
	vpn->openssl_pid = 0;

	gchar *url = g_strdup_printf ("https://%s/vdesk/vpn/connect.php3?resourcename=%s&outform=xml&client_version=1.1", hostname, vpn_z_id);
	gchar *cookie = g_strdup_printf ("MRHSession=%s;", session_key);

	CURL *curl = curl_easy_init ();
	curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, curl_write_to_gstring);
	curl_easy_setopt (curl, CURLOPT_WRITEDATA, vpn->resp);

	curl_easy_setopt (curl, CURLOPT_COOKIE, cookie);
	curl_easy_setopt (curl, CURLOPT_URL, url);

	// necessary?
	curl_easy_setopt (curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Linux) F5Launcher/1.0");

	g_free (url);
	g_free (cookie);
	glib_curl_send (vpn->glc, curl, handle_connection_parameters, vpn);

	return vpn;
}

void
f5vpn_disconnect (F5VpnConnection *connection)
{
	if (connection->ppd_pid)
		kill (connection->ppd_pid, SIGTERM);
	if (connection->openssl_pid)
		kill (connection->openssl_pid, SIGTERM);
}

void
f5vpn_connection_free (F5VpnConnection *connection)
{
	/* f5vpn_connection_free should really only be called after the child processes are reaped */
	g_warn_if_fail (connection->ppd_pid == 0);
	g_warn_if_fail (connection->openssl_pid == 0);

	g_slist_free_full (connection->parsed_lans, free);
	g_slist_free_full (connection->parsed_nameservers, free);

	/* Do NOT free connection->err, it belongs to the library user */
	g_free (connection->session_key);
	g_string_free (connection->resp, TRUE);
	glib_curl_free (connection->glc);
	free (connection);
}
