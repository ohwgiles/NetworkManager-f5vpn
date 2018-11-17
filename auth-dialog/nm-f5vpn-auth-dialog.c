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
#include <errno.h>
#include <gtk/gtk.h>
#include <libnm/NetworkManager.h>
#include <stdio.h>

#include "f5vpn_auth.h"

G_DECLARE_FINAL_TYPE (F5VpnAuthDialog, f5vpn_auth_dialog, F5VPN, AUTH_DIALOG, GtkApplication)

struct _F5VpnAuthDialog
{
	GtkApplication parent;

	struct
	{
		const char *name;
		const char *uuid;
		const char *service;
		gboolean allow_interaction;
	} cmdopts;

	GHashTable *vpn_opts;
	GHashTable *vpn_secrets;

	GtkWidget *root_dialog;
	form_field *const *credential_fields;
	GtkWidget **credential_entries;
	GtkWidget *tunnel_selector;

	F5VpnAuthSession *session;
};

G_DEFINE_TYPE (F5VpnAuthDialog, f5vpn_auth_dialog, GTK_TYPE_APPLICATION)

static void
on_tunnel_selected (GtkDialog *dialog, gint response_id, gpointer user_data)
{
	F5VpnAuthDialog *auth = F5VPN_AUTH_DIALOG (user_data);
	const char *id =
	    gtk_combo_box_get_active_id (GTK_COMBO_BOX (auth->tunnel_selector));

	g_hash_table_insert (auth->vpn_secrets, strdup ("f5vpn-tunnel-id"), strdup (id));

	// finished
	g_application_release (G_APPLICATION (auth));
}

static void
credential_response (F5VpnAuthSession *session, const char *session_key, const vpn_tunnel *const *tunnels, void *userdata, GError *err)
{
	F5VpnAuthDialog *auth = F5VPN_AUTH_DIALOG (userdata);

	if (err) {
		GtkWidget *dialog = gtk_message_dialog_new (GTK_WINDOW (auth->root_dialog), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "Error: %s", err->message);
		gtk_dialog_run (GTK_DIALOG (dialog));
		gtk_widget_destroy (dialog);
		g_application_release (G_APPLICATION (auth));
		return;
	}

	g_hash_table_insert (auth->vpn_secrets, strdup ("f5vpn-session-key"), strdup (session_key));

	g_object_unref (auth->root_dialog);
	auth->root_dialog = gtk_message_dialog_new (NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_QUESTION, GTK_BUTTONS_OK, "Select tunnel");
	GtkWidget *grid = g_object_new (GTK_TYPE_GRID, "column-spacing", 6, "row-spacing", 6, "margin", 6, NULL);
	auth->tunnel_selector = g_object_new (GTK_TYPE_COMBO_BOX_TEXT, NULL);
	for (const vpn_tunnel *const *tp = tunnels; *tp; tp++) {
		gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (auth->tunnel_selector), (*tp)->id, (*tp)->label);
	}
	gtk_combo_box_set_active_id (GTK_COMBO_BOX (auth->tunnel_selector), tunnels[0]->id);

	gtk_grid_attach (GTK_GRID (grid), g_object_new (GTK_TYPE_LABEL, "label", "Tunnel", NULL), 0, 0, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), auth->tunnel_selector, 1, 0, 1, 1);
	gtk_container_add (GTK_CONTAINER (gtk_dialog_get_content_area (GTK_DIALOG (auth->root_dialog))), grid);

	g_signal_connect (auth->root_dialog, "response", G_CALLBACK (on_tunnel_selected), auth);
	gtk_widget_show_all (auth->root_dialog);
}

static void
on_dialog_response (GtkDialog *dialog, gint response_id, gpointer user_data)
{
	F5VpnAuthDialog *auth_dialog = F5VPN_AUTH_DIALOG (user_data);
	GtkWidget *button;

	for (int i = 0, row = 0; auth_dialog->credential_fields[i]; ++i) {
		form_field *field = auth_dialog->credential_fields[i];
		if (field->type == FORM_FIELD_TEXT || field->type == FORM_FIELD_PASSWORD) {
			free (field->value);
			field->value = g_strdup (gtk_entry_get_text (GTK_ENTRY (auth_dialog->credential_entries[row])));
			gtk_widget_set_sensitive (auth_dialog->credential_entries[row], FALSE);
			row++;
		}
	}
	free (auth_dialog->credential_entries);

	if ((button = gtk_dialog_get_widget_for_response (dialog, response_id))) {
		GtkWidget *spinner = gtk_spinner_new ();
		gtk_widget_set_sensitive (button, FALSE);
		gtk_button_set_image (GTK_BUTTON (button), spinner);
		gtk_spinner_start (GTK_SPINNER (spinner));
		gtk_button_set_label (GTK_BUTTON (button), NULL);
	}

	f5vpn_auth_session_post_credentials (auth_dialog->session, credential_response, auth_dialog);
}

static void
on_credentials_needed (F5VpnAuthSession *session, form_field *const *fields, void *userdata, GError *err)
{
	F5VpnAuthDialog *auth_dialog = F5VPN_AUTH_DIALOG (userdata);
	int fields_count;

	char *title = g_strdup_printf ("Enter credentials for %s", (const char *) g_hash_table_lookup (auth_dialog->vpn_opts, "hostname"));
	auth_dialog->root_dialog = gtk_message_dialog_new (NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_QUESTION, GTK_BUTTONS_OK, title);
	g_free (title);

	/* Could how many fields we have */
	for (fields_count = 0; fields[fields_count++];)
		;

	auth_dialog->credential_fields = fields;
	auth_dialog->credential_entries = malloc (sizeof (GtkWidget *) * fields_count);

	GtkWidget *grid = g_object_new (GTK_TYPE_GRID, "column-spacing", 6, "row-spacing", 6, "margin", 6, NULL);
	for (int i = 0, row = 0; fields[i]; ++i) {
		form_field *field = fields[i];
		if (field->type == FORM_FIELD_TEXT || field->type == FORM_FIELD_PASSWORD) {
			GtkWidget *label = g_object_new (GTK_TYPE_LABEL, "label", field->label, NULL);
			auth_dialog->credential_entries[row] = g_object_new (GTK_TYPE_ENTRY, "hexpand", TRUE, "visibility", (field->type != FORM_FIELD_PASSWORD), NULL);
			gtk_grid_attach (GTK_GRID (grid), label, 0, row, 1, 1);
			gtk_grid_attach (GTK_GRID (grid), auth_dialog->credential_entries[i], 1, row, 1, 1);
			row++;
		}
	}

	gtk_container_add (GTK_CONTAINER (gtk_dialog_get_content_area (GTK_DIALOG (auth_dialog->root_dialog))), grid);
	g_signal_connect (auth_dialog->root_dialog, "response", G_CALLBACK (on_dialog_response), auth_dialog);
	gtk_widget_show_all (auth_dialog->root_dialog);
}

static void
activate (GtkApplication *app, gpointer user_data)
{
	F5VpnAuthDialog *auth_dialog = F5VPN_AUTH_DIALOG (app);
	auth_dialog->session = f5vpn_auth_session_new (g_main_context_default (), g_hash_table_lookup (auth_dialog->vpn_opts, "hostname"));

	g_application_hold (G_APPLICATION (app));
	f5vpn_auth_session_begin (auth_dialog->session, on_credentials_needed, auth_dialog);
}

static gint
handle_local_options (GApplication *application, GVariantDict *options, gpointer user_data)
{
	F5VpnAuthDialog *auth_dialog = F5VPN_AUTH_DIALOG (application);

	if (!auth_dialog->cmdopts.allow_interaction)
		return EXIT_FAILURE;

	if (!(auth_dialog->cmdopts.name && auth_dialog->cmdopts.uuid && auth_dialog->cmdopts.service)) {
		fprintf (stderr, "vpn name, uuid and service are required\n");
		return EXIT_FAILURE;
	}

	if (nm_vpn_service_plugin_read_vpn_details (STDIN_FILENO, &auth_dialog->vpn_opts, &auth_dialog->vpn_secrets) == FALSE) {
		fprintf (stderr, "failed to read options and secrets from standard input\n");
		return EXIT_FAILURE;
	}

	return -1;
}

static void
f5vpn_auth_dialog_finalize (GObject *obj)
{
	F5VpnAuthDialog *auth_dialog = F5VPN_AUTH_DIALOG (obj);
	if (auth_dialog->session)
		f5vpn_auth_session_free (auth_dialog->session);
	G_OBJECT_CLASS (f5vpn_auth_dialog_parent_class)->finalize (obj);
}

static void
f5vpn_auth_dialog_class_init (F5VpnAuthDialogClass *klass)
{
	G_OBJECT_CLASS (klass)->finalize = f5vpn_auth_dialog_finalize;
}

static void
f5vpn_auth_dialog_init (F5VpnAuthDialog *auth_dialog)
{
	memset (&auth_dialog->cmdopts, 0, sizeof (auth_dialog->cmdopts));
	auth_dialog->vpn_opts = NULL;
	auth_dialog->vpn_secrets = NULL;
}

int
main (int argc, char **argv)
{
	F5VpnAuthDialog *auth_dialog;
	int status;
	GHashTableIter iter;
	char *key, *value;
	char input[256];

	auth_dialog = g_object_new (f5vpn_auth_dialog_get_type (), "application-id", "org.freedesktop.NetworkManager.f5vpn-auth-dialog", "flags", G_APPLICATION_NON_UNIQUE, NULL);
	/* clang-format off */
	g_application_add_main_option_entries (G_APPLICATION (auth_dialog), (GOptionEntry[]){
	    { "allow-interaction", 'i', 0, G_OPTION_ARG_NONE, &auth_dialog->cmdopts.allow_interaction, "", NULL },
	    { "vpn-name", 'n', 0, G_OPTION_ARG_STRING, &auth_dialog->cmdopts.name, "", NULL },
	    { "vpn-uuid", 'u', 0, G_OPTION_ARG_STRING, &auth_dialog->cmdopts.uuid, "", NULL },
	    { "vpn-service", 's', 0, G_OPTION_ARG_STRING, &auth_dialog->cmdopts.service, "", NULL },
	    { NULL }
	});
	/* clang-format on */

	g_signal_connect (auth_dialog, "activate", G_CALLBACK (activate), NULL);
	g_signal_connect (auth_dialog, "handle-local-options", G_CALLBACK (handle_local_options), NULL);

	status = g_application_run (G_APPLICATION (auth_dialog), argc, argv);

	/* Dump all secrets to stdout */
	g_hash_table_iter_init (&iter, auth_dialog->vpn_secrets);
	while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value))
		printf ("%s\n%s\n", key, value);

	printf ("\n\n");
	fflush (stdout);

	g_object_unref (auth_dialog);

	/* Wait for QUIT from NetworkManager */
	do
		fgets (input, 255, stdin);
	while (strncmp (input, "QUIT", 4) && !errno);

	return status;
}
