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
#include <gio/gio.h>
#include <gio/gunixsocketaddress.h>
#include <gtk/gtk.h>

#include <stdio.h>

G_DEFINE_QUARK (f5vpn - auth - error - quark, f5vpn_auth_error)
#define F5VPN_AUTH_ERROR f5vpn_auth_error_quark ()

static gboolean
parse_uri (const char *uri, gchar **server, gchar **tunnel_id, gchar **otc, GError **err)
{
	g_autofree gchar *scheme = NULL, *query = NULL;
	if (g_uri_split (uri, G_URI_FLAGS_NONE, &scheme, NULL, NULL, NULL, NULL, &query, NULL, err) == FALSE) {
		return FALSE;
	}

	if (!scheme || strcmp (scheme, "f5-vpn") != 0) {
		*err = g_error_new (F5VPN_AUTH_ERROR, 0, "Incorrect URI scheme, expected 'f5-vpn', got '%s'", scheme ? scheme : "(NULL)");
		return FALSE;
	}

	if (!query) {
		*err = g_error_new (F5VPN_AUTH_ERROR, 0, "Could not parse query params from uri");
		return FALSE;
	}

	GUriParamsIter iter;
	gchar *unowned_attr, *unowned_value, *found_server = NULL, *found_tunnel_id = NULL, *found_otc = NULL;
	GError *local_err = NULL;

	g_uri_params_iter_init (&iter, query, -1, "&", G_URI_PARAMS_NONE);
	while (g_uri_params_iter_next (&iter, &unowned_attr, &unowned_value, &local_err)) {
		g_autofree gchar *attr = g_steal_pointer (&unowned_attr);
		gchar *value = g_steal_pointer (&unowned_value);
		if (strcmp (attr, "server") == 0) {
			found_server = value;
		} else if (strcmp (attr, "otc") == 0) {
			found_otc = value;
		} else if (strcmp (attr, "resourcename") == 0) {
			found_tunnel_id = value;
		} else {
			free (value);
		}
	}

	if (local_err) {
		free (found_server);
		free (found_tunnel_id);
		free (found_otc);
		*err = local_err;
		return FALSE;
	}

	if (!found_server || !found_tunnel_id || !found_otc) {
		*err = g_error_new (F5VPN_AUTH_ERROR, 0, "f5vpn scheme URI missing query parameters 'tunnel_id' or 'otc'");
		return FALSE;
	}

	*server = found_server;
	*tunnel_id = found_tunnel_id;
	*otc = found_otc;
	return TRUE;
}

static gboolean
write_otc_to_auth_dialog (const char *server, const char *tunnel_id, const char *otc, GError **err)
{
	GSocketClient *client = g_socket_client_new ();
	g_socket_client_set_socket_type (client, G_SOCKET_TYPE_SEQPACKET);

	gchar *sockname = g_strdup_printf ("nm-f5vpn-browser-auth,uid=%d,server=%s", getuid (), server);
	GSocketAddress *addr = g_unix_socket_address_new_with_type (sockname, -1, G_UNIX_SOCKET_ADDRESS_ABSTRACT);
	free (sockname);

	GSocketConnection *conn = g_socket_client_connect (client, G_SOCKET_CONNECTABLE (addr), NULL, err);
	if (!conn)
		return FALSE;

	GOutputStream *out = g_io_stream_get_output_stream (G_IO_STREAM (conn));

	if (g_output_stream_write_all (out, tunnel_id, strlen (tunnel_id), NULL, NULL, err) == FALSE)
		return FALSE;

	if (g_output_stream_write_all (out, otc, strlen (otc), NULL, NULL, err) == FALSE)
		return FALSE;

	return TRUE;
}

static void
error_popup (GError *err)
{
	GtkWidget *dialog = gtk_message_dialog_new (GTK_WINDOW (NULL), 0, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "Error: %s", err->message);
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
	g_error_free (err);
}

int
main (int argc, char **argv)
{

	gchar *server, *tunnel_id, *otc;
	GError *err = NULL;

	if (argc != 2) {
		fprintf (stderr, "Expected usage: nm-f5vpn-xdg-helper F5VPN_SCHEME_URI\n");
		return 1;
	}

	gtk_init (&argc, &argv);

	if (!parse_uri (argv[1], &server, &tunnel_id, &otc, &err)) {
		error_popup (err);
		return 1;
	}

	if (!write_otc_to_auth_dialog (server, tunnel_id, otc, &err)) {
		error_popup (err);
		return 1;
	}

	return 0;
}
