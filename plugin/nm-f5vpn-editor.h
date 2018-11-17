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
#ifndef NM_F5VPN_EDITOR_H
#define NM_F5VPN_EDITOR_H

#include <libnm/NetworkManager.h>

#define F5VPN_TYPE_EDITOR (f5vpn_editor_get_type ())

#define F5VPN_EDITOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), F5VPN_TYPE_EDITOR, F5VpnEditor))
#define F5VPN_EDITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), F5VPN_TYPE_EDITOR, F5VpnEditorClass))
#define F5VPN_IS_EDITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), F5VPN_TYPE_EDITOR))
#define F5VPN_IS_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), F5VPN_TYPE_EDITOR))
#define F5VPN_EDITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), F5VPN_TYPE_EDITOR, F5VpnEditorClass))

typedef struct _F5VpnEditor F5VpnEditor;
typedef struct _F5VpnEditorClass F5VpnEditorClass;

struct _F5VpnEditor
{
	GObject parent;
};

struct _F5VpnEditorClass
{
	GObjectClass parent;
};

GType f5vpn_editor_get_type (void);

NMVpnEditor *f5vpn_editor_new (NMConnection *connection, GError **error);

#endif // NM_F5VPN_EDITOR_H
