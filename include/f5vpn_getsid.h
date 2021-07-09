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
#ifndef F5VPN_GETSID_H
#define F5VPN_GETSID_H

#include <glib.h>

struct _F5VpnGetSid;
typedef struct _F5VpnGetSid F5VpnGetSid;

/**
 * Callback function to be passed to f5vpn_getsid_begin.
 * The consumer of this callback should first check whether there were errors
 * (err is non-NULL) and abort the process (and call f5vpn_getsid_free) if so.
 */
typedef void (*F5VpnGetSidResultCallback) (F5VpnGetSid *getsid, const char *sid, void *userdata, GError *err);

/**
 * Sends a request to the VPN host to exchange a One-Time-Code for a valid
 * session ID. Since the session is asynchronous, pass a GMainContext pointer
 * (or use NULL to use the default context). This context will provide the
 * event loop in which the network functions will run. The host argument will
 * form the HTTPS URL where the F5 VPN server may be found.
 *
 * The returned pointer should be freed with f5vpn_getsid_free.
 */
F5VpnGetSid *f5vpn_getsid_begin (GMainContext *glib_context, const char *host, const char *otc, F5VpnGetSidResultCallback callback, void *userdata);

/**
 * Destroys a F5VpnGetSid structure and frees all associated memory
 */
void f5vpn_getsid_free (F5VpnGetSid *getsid);

#endif // F5VPN_GETSID_H
