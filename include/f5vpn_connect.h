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
#ifndef F5VPN_CONNECT_H
#define F5VPN_CONNECT_H

#include <glib.h>
#include <stdint.h>
#include <netinet/in.h>

struct _F5VpnConnection;
typedef struct _F5VpnConnection F5VpnConnection;

enum
{
	F5VPN_CONNECT_ERROR_BAD_HTTP_CODE = 10001,
	F5VPN_CONNECT_ERROR_PARSE_FAILED
};

typedef struct
{
	struct in_addr addr;
	unsigned char mask;
} LanAddr;

typedef struct
{
	uint32_t local_ip;
	uint32_t remote_ip;
	GSList *lans; // data is of type LanAddr*
	GSList *nameservers; // data is of type struct in_addr*
	char device[16];
} NetworkSettings;

typedef void (*F5VpnConnectCallback) (F5VpnConnection *connection, const NetworkSettings *settings, void *userdata, GError *err);

F5VpnConnection *f5vpn_connect (GMainContext *main_context, const char *hostname, const char *session_key, const char *vpn_z_id, F5VpnConnectCallback callback, void *userdata);

void f5vpn_disconnect (F5VpnConnection *connection);

void f5vpn_connection_free (F5VpnConnection *connection);

#endif // F5VPN_CONNECT_H
