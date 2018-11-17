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
#ifndef F5VPN_AUTH_H
#define F5VPN_AUTH_H

#include <glib.h>

struct _F5VpnAuthSession;
typedef struct _F5VpnAuthSession F5VpnAuthSession;

typedef enum
{
	FORM_FIELD_TEXT,
	FORM_FIELD_PASSWORD,
	FORM_FIELD_HIDDEN,
	FORM_FIELD_OTHER
} form_field_type;

/**
 * Structure represents form fields such as username and password
 * which might be requested by the login form. See
 * F5VpnRequestCredentialsCallback
 */
typedef struct
{
	char *label;
	char *name;
	char *value;
	form_field_type type;
} form_field;

/**
 * Structure describes VPN tunnels offered to the user after successful auth
 */
typedef struct
{
	char *id;
	char *label;
	char *description;
	gboolean autoconnect;
} vpn_tunnel;

/**
 * Callback function to be passed to f5vpn_auth_session_begin. The provider
 * of this callback should first check whether there were errors (err is
 * non-NULL) and abort the process (and call f5vpn_auth_session_free) if so.
 * If there was no error, then enumerate the NULL-terminated list of fields
 * requested by the login form, prompt the user for values if necessary,
 * and update the structure by calling free() on field->value and replacing
 * field->value with a newly-allocated string. F5VpnAuthSession will take
 * ownership of this memory.
 */
typedef void (*F5VpnRequestCredentialsCallback) (F5VpnAuthSession *session, form_field *const *fields, void *userdata, GError *err);

/**
 * Callback function to be passed to f5vpn_auth_session_post_credentials.
 * The provider of this callback should first check whether there were errors
 * (err is non-NULL) and abort the process (and call f5vpn_auth_session_free)
 * if so. If there was no error, then the authentication process completed
 * sucessfully, and the f5vpn_connect flow may begin; this will require the
 * session key and one of the vpn tunnel IDs provided by this function. These
 * pointers will remain valid until f5vpn_auth_session_free is called.
 */
typedef void (*F5VpnLoginDoneCallback) (F5VpnAuthSession *session, const char *session_key, const vpn_tunnel *const *tunnels, void *userdata, GError *err);

/**
 * Creates a new authentication session. Since the session is asynchronous,
 * pass a GMainContext pointer (or use NULL to use the default context).
 * This context will provide the event loop in which the network functions
 * will run. The host argument will form the HTTPS URL where the F5 VPN
 * server may be found.
 *
 * The returned session pointer should be used to begin a session with
 * f5vpn_auth_session_begin, and once authentication is completed, should
 * be freed with f5vpn_auth_session_free.
 */
F5VpnAuthSession *f5vpn_auth_session_new (GMainContext *glib_context, const char *host);

/**
 * Begins a new session. This will start network operations; some time later
 * the passed callback will be invoked to request credentials or report an
 * error. The callback function should retrieve credentials from the user and
 * then call f5vpn_auth_session_post_credentials.
 */
void f5vpn_auth_session_begin (F5VpnAuthSession *session, F5VpnRequestCredentialsCallback callback, void *userdata);

/**
 * Posts the updated credentials to the server. This is performed
 * asynchronously, some time later the passed callback will be invoked to
 * present the session key and a list of available VPN tunnels. After this the
 * authentication flow is complete and the caller should free the
 * F5VpnAuthSession.
 */
void f5vpn_auth_session_post_credentials (F5VpnAuthSession *session, F5VpnLoginDoneCallback callback, void *userdata);

/**
 * Destroys a F5VpnAuthSession structure and frees all associated memory
 */
void f5vpn_auth_session_free (F5VpnAuthSession *session);

#endif // F5VPN_AUTH_H
