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
#include "nm-f5vpn-editor.h"
#include <gtk/gtk.h>

typedef struct
{
	GtkWidget *entry_hostname;
	GtkWidget *root_widget;
} F5VpnEditorPrivate;

static void f5vpn_editor_nm_vpn_editor_interface_init (NMVpnEditorInterface *iface_class);

G_DEFINE_TYPE_WITH_CODE (F5VpnEditor, f5vpn_editor, G_TYPE_OBJECT, G_ADD_PRIVATE (F5VpnEditor) G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR, f5vpn_editor_nm_vpn_editor_interface_init))

static GObject *
get_widget (NMVpnEditor *iface)
{
	F5VpnEditorPrivate *priv = f5vpn_editor_get_instance_private (F5VPN_EDITOR (iface));
	g_object_ref_sink (priv->root_widget);
	return G_OBJECT (priv->root_widget);
}

/* Check if user inputs are valid and update NMSettingVpn if so. Called on every keystroke. */
static gboolean
update_connection (NMVpnEditor *iface, NMConnection *connection, GError **error)
{
	(void) error;

	F5VpnEditor *self = F5VPN_EDITOR (iface);
	F5VpnEditorPrivate *priv = f5vpn_editor_get_instance_private (self);
	NMSettingVpn *svpn;

	svpn = nm_connection_get_setting_vpn (connection);
	g_assert_nonnull (svpn);

	const gchar *hostname = gtk_entry_get_text (GTK_ENTRY (priv->entry_hostname));
	if (!hostname || !*hostname)
		return FALSE;

	nm_setting_vpn_add_data_item (svpn, "hostname", hostname);

	return TRUE;
}

static void
f5vpn_editor_dispose (GObject *obj)
{
	F5VpnEditor *editor = F5VPN_EDITOR (obj);
	F5VpnEditorPrivate *priv = f5vpn_editor_get_instance_private (editor);
	g_clear_object (&priv->root_widget);
	G_OBJECT_CLASS (f5vpn_editor_parent_class)->dispose (obj);
}

static void
f5vpn_editor_init (F5VpnEditor *plugin)
{
	(void) plugin;
}

static void
f5vpn_editor_nm_vpn_editor_interface_init (NMVpnEditorInterface *iface_class)
{
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

static void
f5vpn_editor_class_init (F5VpnEditorClass *klass)
{
	GObjectClass *goc = G_OBJECT_CLASS (klass);
	goc->dispose = f5vpn_editor_dispose;
}

static void
host_entry_changed (NMVpnEditor *editor)
{
	g_signal_emit_by_name (editor, "changed", NULL);
}

GtkWidget *
create_root_widget (F5VpnEditor *editor, NMSettingVpn *svpn)
{
	F5VpnEditorPrivate *priv = f5vpn_editor_get_instance_private (editor);

	const char *hostname = nm_setting_vpn_get_data_item (svpn, "hostname");
	if (!hostname)
		hostname = "";

	GtkWidget *grid = g_object_new (GTK_TYPE_GRID, "column-spacing", 12, "margin", 12, NULL);
	GtkWidget *host_label = g_object_new (GTK_TYPE_LABEL, "label", "Hostname", NULL);
	GtkWidget *entry_hostname = g_object_new (GTK_TYPE_ENTRY, "hexpand", TRUE, "text", hostname, NULL);
	priv->entry_hostname = entry_hostname;

	g_signal_connect_swapped (entry_hostname, "changed", G_CALLBACK (host_entry_changed), editor);

	gtk_grid_attach (GTK_GRID (grid), host_label, 0, 0, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), entry_hostname, 1, 0, 1, 1);

	return grid;
}

NMVpnEditor *
f5vpn_editor_new (NMConnection *connection, GError **error)
{
	(void) error;

	F5VpnEditor *editor = g_object_new (F5VPN_TYPE_EDITOR, NULL);
	F5VpnEditorPrivate *priv = f5vpn_editor_get_instance_private (editor);

	NMSettingVpn *svpn;

	svpn = nm_connection_get_setting_vpn (connection);
	priv->root_widget = create_root_widget (editor, svpn);

	return NM_VPN_EDITOR (editor);
}
