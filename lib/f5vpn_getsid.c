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
#include "f5vpn_getsid.h"
#include "glib_curl.h"

G_DEFINE_QUARK (f5vpn - getsid - error - quark, f5vpn_getsid_error)
#define F5VPN_GETSID_ERROR f5vpn_getsid_error_quark ()

#ifdef WITH_DEBUG
#define debug(...) fprintf (stderr, __VA_ARGS__)
#else
#define debug(...)
#endif

struct _F5VpnGetSid
{
	F5VpnGetSidResultCallback callback;
	void *userdata;
	GlibCurl *glc;
	struct curl_slist *headers;
	gchar *sid;
	GError *err;
};

static gboolean
report_getsid_state (gpointer user)
{
	F5VpnGetSid *getsid = (F5VpnGetSid *) user;
	(getsid->callback) (getsid, getsid->sid, getsid->userdata, getsid->err);
	getsid->err = NULL;
	return G_SOURCE_REMOVE;
}

void
on_get_sessid_response (CURL *curl, void *user, GError *err)
{
	F5VpnGetSid *getsid = (F5VpnGetSid *) user;
	long response_code;

	if (err) {
		getsid->err = err;
		getsid->callback (getsid, NULL, getsid->userdata, err);
		curl_easy_cleanup (curl);
		g_timeout_add (0, report_getsid_state, getsid);
		return;
	}

	curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response_code);
	if (response_code != 200) {
		getsid->err = g_error_new (F5VPN_GETSID_ERROR, 0, "Unexpected HTTP response code %lu received", response_code);
		curl_easy_cleanup (curl);
		g_timeout_add (0, report_getsid_state, getsid);
		return;
	}

	curl_easy_cleanup (curl);

	if (getsid->sid == NULL) {
		getsid->err = g_error_new (F5VPN_GETSID_ERROR, 0, "%s", "Failed to parse X-ACCESS-Session-ID header from response");
		g_timeout_add (0, report_getsid_state, getsid);
		return;
	}

	// all good
	g_timeout_add (0, report_getsid_state, getsid);
}

static size_t
header_callback (char *buffer, size_t size, size_t nitems, void *user)
{
	F5VpnGetSid *getsid = (F5VpnGetSid *) user;
	const char expected[] = "X-ACCESS-Session-ID: ";
	size_t elen = strlen (expected);

	if (getsid->sid == NULL && nitems - strlen ("\r\n") > elen && strncmp (expected, buffer, elen) == 0) {
		getsid->sid = strndup (&buffer[elen], nitems - strlen ("\r\n") - elen);
	}

	return nitems * size;
}

F5VpnGetSid *
f5vpn_getsid_begin (GMainContext *glib_context, const char *host, const char *otc, F5VpnGetSidResultCallback callback, void *userdata)
{
	F5VpnGetSid *getsid = malloc (sizeof (F5VpnGetSid));
	getsid->glc = glib_curl_new (glib_context);
	getsid->callback = callback;
	getsid->userdata = userdata;
	getsid->headers = NULL;
	getsid->sid = NULL;
	getsid->err = NULL;

	CURL *curl = curl_easy_init ();
	curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 1L);
#ifdef WITH_DEBUG
	curl_easy_setopt (curl, CURLOPT_VERBOSE, 1L);
#endif

	curl_easy_setopt (curl, CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt (curl, CURLOPT_HEADERDATA, getsid);

	gchar *url = g_strdup_printf ("https://%s/vdesk/get_sessid_for_token.php3", host);
	curl_easy_setopt (curl, CURLOPT_URL, url);
	g_free (url);

	gchar *access_header = g_strdup_printf ("X-ACCESS-Session-Token: %s", otc);
	getsid->headers = curl_slist_append (getsid->headers, access_header);
	g_free (access_header);
	curl_easy_setopt (curl, CURLOPT_HTTPHEADER, getsid->headers);

	curl_easy_setopt (curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Linux) F5Launcher/1.0");

	glib_curl_send (getsid->glc, curl, on_get_sessid_response, getsid);

	return getsid;
}

void
f5vpn_getsid_free (F5VpnGetSid *getsid)
{
	free (getsid->sid);
	curl_slist_free_all (getsid->headers);
	glib_curl_free (getsid->glc);
	free (getsid);
}
