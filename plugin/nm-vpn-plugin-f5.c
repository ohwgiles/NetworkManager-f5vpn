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
#include <gmodule.h>
#include <libnm/NetworkManager.h>

#define NM_VPN_SERVICE_TYPE_F5VPN "org.freedesktop.NetworkManager.f5vpn"
#define F5VPN_PLUGIN_NAME         "F5 SSL VPN"
#define F5VPN_PLUGIN_DESC         "Connect to F5 SSL VPNs."

#define F5VPN_TYPE_EDITOR_PLUGIN    (f5vpn_editor_plugin_get_type ())
#define F5VPN_IS_EDITOR_PLUGIN(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), F5VPN_TYPE_EDITOR_PLUGIN))

typedef struct _F5VpnEditorPlugin F5VpnEditorPlugin;
typedef struct _F5VpnEditorPluginClass F5VpnEditorPluginClass;

struct _F5VpnEditorPlugin
{
	GObject parent;
};

struct _F5VpnEditorPluginClass
{
	GObjectClass parent;
};

static void
f5vpn_editor_plugin_interface_init (NMVpnEditorPluginInterface *klass);

G_DEFINE_TYPE_EXTENDED (F5VpnEditorPlugin, f5vpn_editor_plugin, G_TYPE_OBJECT, 0, G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR_PLUGIN, f5vpn_editor_plugin_interface_init))

enum
{
	PROP_0,
	PROP_NAME,
	PROP_DESC,
	PROP_SERVICE
};

static void
get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, F5VPN_PLUGIN_NAME);
		break;
	case PROP_DESC:
		g_value_set_string (value, F5VPN_PLUGIN_DESC);
		break;
	case PROP_SERVICE:
		g_value_set_string (value, NM_VPN_SERVICE_TYPE_F5VPN);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
f5vpn_editor_plugin_init (F5VpnEditorPlugin *obj)
{
	(void) obj;
}

static guint32
get_capabilities (NMVpnEditorPlugin *iface)
{
	(void) iface;

	return NM_VPN_EDITOR_PLUGIN_CAPABILITY_NONE;
}

NMVpnEditor *f5vpn_editor_new (NMConnection *connection, GError **error);

static NMVpnEditor *
get_editor (NMVpnEditorPlugin *iface, NMConnection *connection, GError **error)
{
	g_return_val_if_fail (F5VPN_IS_EDITOR_PLUGIN (iface), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	return f5vpn_editor_new (connection, error);
}

static void
f5vpn_editor_plugin_interface_init (NMVpnEditorPluginInterface *klass)
{
	klass->get_editor = get_editor;
	klass->get_capabilities = get_capabilities;
}

static void
f5vpn_editor_plugin_class_init (F5VpnEditorPluginClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->get_property = get_property;
	g_object_class_override_property (object_class, PROP_NAME, NM_VPN_EDITOR_PLUGIN_NAME);
	g_object_class_override_property (object_class, PROP_DESC, NM_VPN_EDITOR_PLUGIN_DESCRIPTION);
	g_object_class_override_property (object_class, PROP_SERVICE, NM_VPN_EDITOR_PLUGIN_SERVICE);
}

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory (GError **error)
{
	g_return_val_if_fail (!error || !*error, NULL);

	return g_object_new (F5VPN_TYPE_EDITOR_PLUGIN, NULL);
}
