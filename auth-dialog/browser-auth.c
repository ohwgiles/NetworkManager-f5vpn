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
#include <fcntl.h>
#include <gio/gunixsocketaddress.h>
#include <gtk/gtk.h>

#include "auth-dialog.h"

static void
on_otc_retrieved (F5VpnGetSid *getsid, const char *session_key, void *userdata, GError *err)
{
	(void) getsid;

	F5VpnAuthDialog *auth = F5VPN_AUTH_DIALOG (userdata);

	if (err) {
		GtkWidget *dialog = gtk_message_dialog_new (GTK_WINDOW (auth->root_dialog), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "Error: %s", err->message);
		gtk_dialog_run (GTK_DIALOG (dialog));
		gtk_widget_destroy (dialog);
	} else {
		g_hash_table_insert (auth->vpn_secrets, strdup ("f5vpn-session-key"), strdup (session_key));
	}

	// finished
	g_application_release (G_APPLICATION (auth));
}

static gboolean
on_incoming_connection (GSocketService *service, GSocketConnection *conn, GObject *src_obj, gpointer user_data)
{
	(void) service;
	(void) src_obj;

	F5VpnAuthDialog *auth = F5VPN_AUTH_DIALOG (user_data);

	GInputStream *in = g_io_stream_get_input_stream (G_IO_STREAM (conn));

	static char buffer[4096];
	GError *err = NULL;
	int n;

	n = g_input_stream_read (in, buffer, 4095, NULL, &err);
	if (n == -1) {
		fprintf (stderr, "error reading from client: %s\n", err->message);
		return TRUE;
	}
	g_hash_table_insert (auth->vpn_secrets, strdup ("f5vpn-tunnel-id"), strndup (buffer, n));

	n = g_input_stream_read (in, buffer, 4095, NULL, &err);
	if (n == -1) {
		fprintf (stderr, "error reading from client: %s\n", err->message);
		return TRUE;
	}

	gchar *otc = strndup (buffer, n);
	auth->getsid = f5vpn_getsid_begin (g_main_context_default (), g_hash_table_lookup (auth->vpn_opts, "hostname"), otc, on_otc_retrieved, auth);
	free (otc);

	return TRUE;
}

static void
on_dialog_response (GtkDialog *dialog, gint response_id, gpointer user_data)
{
	(void) dialog;
	(void) response_id;

	F5VpnAuthDialog *auth = F5VPN_AUTH_DIALOG (user_data);
	g_object_unref (auth->root_dialog);
	g_application_release (G_APPLICATION (auth));
}

void
browser_auth_begin (F5VpnAuthDialog *auth)
{
	GSocketService *server = g_socket_service_new ();

	gchar *sockname = g_strdup_printf ("nm-f5vpn-browser-auth,uid=%d,server=%s", getuid (), (char *) g_hash_table_lookup (auth->vpn_opts, "hostname"));
	GSocketAddress *addr = g_unix_socket_address_new_with_type (sockname, -1, G_UNIX_SOCKET_ADDRESS_ABSTRACT);
	free (sockname);

	GError *err = NULL;
	gboolean res = g_socket_listener_add_address (G_SOCKET_LISTENER (server),
	                                              addr,
	                                              G_SOCKET_TYPE_SEQPACKET,
	                                              G_SOCKET_PROTOCOL_DEFAULT,
	                                              NULL,
	                                              NULL,
	                                              &err);

	if (!res) {
		GtkWidget *dialog = gtk_message_dialog_new (NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "Error: %s", err->message);
		gtk_dialog_run (GTK_DIALOG (dialog));
		gtk_widget_destroy (dialog);
		g_application_release (G_APPLICATION (auth));
		return;
	}

	g_signal_connect (server, "incoming", G_CALLBACK (on_incoming_connection), auth);

	// g_app_info_launch_default_for_uri unfortunately leaks stdout/stderr of launched process, hence this nastiness
	if (fork () == 0) {
		close (1);
		open ("/dev/null", O_WRONLY);
		char *url = g_strdup_printf ("https://%s", g_hash_table_lookup (auth->vpn_opts, "hostname"));
		execlp ("xdg-open", "xdg-open", url, NULL);
		_exit (1);
	}

	auth->root_dialog = gtk_message_dialog_new (NULL,
	                                            GTK_DIALOG_MODAL,
	                                            GTK_MESSAGE_ERROR,
	                                            GTK_BUTTONS_CANCEL,
	                                            "Launching \"xdg-open https://%s\".\n\n"
	                                            "Please authenticate with the browser, select a tunnel "
	                                            "and open the resulting f5-vpn:// scheme URI with "
	                                            "\"F5Vpn Browser Authentication Helper\".\n\n"
	                                            "Waiting for browser authentication...",
	                                            g_hash_table_lookup (auth->vpn_opts, "hostname"));
	GList *cw = gtk_container_get_children (GTK_CONTAINER (gtk_message_dialog_get_message_area (GTK_MESSAGE_DIALOG (auth->root_dialog))));
	gtk_label_set_justify (GTK_LABEL (cw->data), GTK_JUSTIFY_CENTER);
	g_list_free (cw);

	GtkWidget *spinner = gtk_spinner_new ();
	gtk_spinner_start (GTK_SPINNER (spinner));
	gtk_container_add (GTK_CONTAINER (gtk_dialog_get_content_area (GTK_DIALOG (auth->root_dialog))), spinner);
	g_signal_connect (auth->root_dialog, "response", G_CALLBACK (on_dialog_response), auth);
	gtk_widget_show_all (auth->root_dialog);
}
