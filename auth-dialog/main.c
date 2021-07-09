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

#include "auth-dialog.h"
#include "f5vpn_auth.h"

G_DEFINE_TYPE (F5VpnAuthDialog, f5vpn_auth_dialog, GTK_TYPE_APPLICATION)

static void
activate (GtkApplication *app, gpointer user_data)
{
	(void) user_data;

	g_application_hold (G_APPLICATION (app));
	F5VpnAuthDialog *auth_dialog = F5VPN_AUTH_DIALOG (app);

	const char *use_browser_auth = g_hash_table_lookup (auth_dialog->vpn_opts, "use-browser-auth");
	if (use_browser_auth && strcmp (use_browser_auth, "true") == 0) {
		browser_auth_begin (auth_dialog);
	} else {
		native_auth_begin (auth_dialog);
	}
}

static gint
handle_local_options (GApplication *application, GVariantDict *options, gpointer user_data)
{
	(void) options;
	(void) user_data;

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
	if (auth_dialog->getsid)
		f5vpn_getsid_free (auth_dialog->getsid);
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
	char *key, *value, *ev;
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
	if (auth_dialog->vpn_secrets) {
		g_hash_table_iter_init (&iter, auth_dialog->vpn_secrets);
		while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value))
			printf ("%s\n%s\n", key, value);
	}

	printf ("\n\n");
	fflush (stdout);

	g_object_unref (auth_dialog);

	/* Wait for QUIT from NetworkManager */
	do
		ev = fgets (input, 255, stdin);
	while (strncmp (input, "QUIT", 4) && ev != NULL);

	return status;
}
