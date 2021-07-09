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
#include <gtk/gtk.h>

#include "f5vpn_auth.h"
#include "f5vpn_getsid.h"

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
	F5VpnGetSid *getsid;
};

void browser_auth_begin (F5VpnAuthDialog *auth);

void native_auth_begin (F5VpnAuthDialog *auth_dialog);
