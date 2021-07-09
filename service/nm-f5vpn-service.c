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
#include <arpa/inet.h>
#include <curl/curl.h>
#include <glib.h>
#include <libnm/NetworkManager.h>

#include "f5vpn_connect.h"

#define NM_TYPE_F5VPN_PLUGIN (nm_f5vpn_plugin_get_type ())
#define NM_F5VPN_PLUGIN(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_F5VPN_PLUGIN, NMF5VpnPlugin))
#define NM_F5VPN_PLUGIN_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_F5VPN_PLUGIN, NMF5VnPluginClass))
#define NM_IS_F5VPN_PLUGIN(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_F5VPN_PLUGIN))
#define NM_IS_F5VPN_PLUGIN_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_F5VPN_PLUGIN))
#define NM_F5VPN_PLUGIN_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_F5VPN_PLUGIN, NMF5VpnPluginClass))

typedef struct
{
	NMVpnServicePlugin parent;
	F5VpnConnection *f5vpn;
} NMF5VpnPlugin;

typedef struct
{
	NMVpnServicePluginClass parent;
} NMF5VpnPluginClass;

typedef struct
{
	NMVpnServicePlugin *plugin;
	NMConnection *nm_connection;
} PluginConnectionHandle;

G_DEFINE_TYPE (NMF5VpnPlugin, nm_f5vpn_plugin, NM_TYPE_VPN_SERVICE_PLUGIN)

static GMainLoop *main_loop;

static GVariant *
build_dns (const NetworkSettings *settings)
{
	GVariantBuilder builder;
	GVariant *value;
	gint size = 0;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("au"));

	for (GSList *p = settings->nameservers; p; p = p->next, size++) {
		g_variant_builder_add_value (&builder, g_variant_new_uint32 (((struct in_addr *) p->data)->s_addr));
	}

	value = g_variant_builder_end (&builder);
	if (size == 0) {
		g_variant_unref (value);
		return NULL;
	}

	return value;
}

static GVariant *
build_routes (const NetworkSettings *settings)
{
	GVariantBuilder builder;
	GVariant *value;
	gint size = 0;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aau"));

	for (GSList *p = settings->lans; p; p = p->next, size++) {
		GVariantBuilder array;
		g_variant_builder_init (&array, G_VARIANT_TYPE ("au"));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (((LanAddr *) p->data)->addr.s_addr));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (((LanAddr *) p->data)->mask));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (settings->remote_ip));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (0u));
		g_variant_builder_add_value (&builder, g_variant_builder_end (&array));
	}

	value = g_variant_builder_end (&builder);
	if (size == 0) {
		g_variant_unref (value);
		return NULL;
	}

	return value;
}

static void
notify_network_settings (NMVpnServicePlugin *plugin, const NetworkSettings *settings)
{
	GVariantBuilder vb_conf, vb_ip4;
	GVariant *var;

	g_variant_builder_init (&vb_conf, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&vb_conf, "{sv}", NM_VPN_PLUGIN_CONFIG_HAS_IP4, g_variant_new_boolean (TRUE));
	g_variant_builder_add (&vb_conf, "{sv}", NM_VPN_PLUGIN_CONFIG_TUNDEV, g_variant_new_string (settings->device));

	nm_vpn_service_plugin_set_config (plugin, g_variant_builder_end (&vb_conf));

	g_variant_builder_init (&vb_ip4, G_VARIANT_TYPE_VARDICT);

	g_variant_builder_add (&vb_ip4, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, g_variant_new_uint32 (settings->local_ip));
	g_variant_builder_add (&vb_ip4, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_PTP, g_variant_new_uint32 (settings->remote_ip));
	g_variant_builder_add (&vb_ip4, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, g_variant_new_uint32 (32));

	if ((var = build_routes (settings))) {
		g_variant_builder_add (&vb_ip4, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ROUTES, var);
		g_variant_builder_add (&vb_ip4, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT, g_variant_new_boolean (TRUE));
	}

	if ((var = build_dns (settings))) {
		g_variant_builder_add (&vb_ip4, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_DNS, var);
	}
	nm_vpn_service_plugin_set_ip4_config (plugin, g_variant_builder_end (&vb_ip4));
}

static void
on_tunnel_status_change (F5VpnConnection *connection, const NetworkSettings *settings, void *userdata, GError *err)
{
	PluginConnectionHandle *pch = (PluginConnectionHandle *) userdata;

	if (err) {
		if (err->code == F5VPN_CONNECT_ERROR_BAD_HTTP_CODE) {
			/* Don't know how to clear secrets from here. Instead, do a synchronous test in need_secrets, which will be called on reconnect */
			nm_connection_need_secrets (pch->nm_connection, NULL);
		}
		g_object_unref (pch->nm_connection);
		nm_vpn_service_plugin_failure (pch->plugin, NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		f5vpn_connection_free (connection);
		NM_F5VPN_PLUGIN (pch->plugin)->f5vpn = NULL;
		free (pch);
		return;
	}

	if (!settings) {
		g_object_unref (pch->nm_connection);
		nm_vpn_service_plugin_disconnect (pch->plugin, NULL);
		f5vpn_connection_free (connection);
		NM_F5VPN_PLUGIN (pch->plugin)->f5vpn = NULL;
		free (pch);
		return;
	}

	notify_network_settings (pch->plugin, settings);
}

static gboolean
nm_f5vpn_connect (NMVpnServicePlugin *plugin, NMConnection *connection, GError **error)
{
	(void) error;

	NMSettingVpn *s_vpn;

	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	PluginConnectionHandle *pch = malloc (sizeof (PluginConnectionHandle));
	pch->plugin = plugin;
	pch->nm_connection = connection;
	g_object_ref_sink (connection);
	NM_F5VPN_PLUGIN (plugin)->f5vpn =
	    f5vpn_connect (g_main_loop_get_context (main_loop),
	                   nm_setting_vpn_get_data_item (s_vpn, "hostname"),
	                   nm_setting_vpn_get_secret (s_vpn, "f5vpn-session-key"),
	                   nm_setting_vpn_get_secret (s_vpn, "f5vpn-tunnel-id"),
	                   on_tunnel_status_change, pch);
	nm_connection_clear_secrets (pch->nm_connection);

	return TRUE;
}

static gboolean
nm_f5vpn_need_secrets (NMVpnServicePlugin *plugin, NMConnection *connection, const char **setting_name, GError **error)
{
	NMSettingVpn *s_vpn;

	g_assert_true (NM_IS_VPN_SERVICE_PLUGIN (plugin));
	g_assert_true (NM_IS_CONNECTION (connection));

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION, "%s", "Could not process the request because the VPN connection settings were invalid.");
		return FALSE;
	}

	if (nm_setting_vpn_get_secret (s_vpn, "f5vpn-tunnel-id") == NULL) {
		*setting_name = "f5vpn-tunnel-id";
		return TRUE;
	}

	if (nm_setting_vpn_get_secret (s_vpn, "f5vpn-session-key") == NULL) {
		*setting_name = "f5vpn-session-key";
		return TRUE;
	}

	/* Synchronously call the connect endpoint, because we don't know if the session key is valid,
	 * and I don't know how to report it when the connection fails asynchronously later */
	gchar *url = g_strdup_printf ("https://%s/vdesk/vpn/connect.php3?resourcename=%s&outform=xml&client_version=1.1", nm_setting_vpn_get_data_item (s_vpn, "hostname"), nm_setting_vpn_get_secret (s_vpn, "f5vpn-tunnel-id"));
	gchar *cookie = g_strdup_printf ("MRHSession=%s;", nm_setting_vpn_get_secret (s_vpn, "f5vpn-session-key"));

	CURL *curl = curl_easy_init ();
	curl_easy_setopt (curl, CURLOPT_COOKIE, cookie);
	curl_easy_setopt (curl, CURLOPT_URL, url);

	g_free (url);
	g_free (cookie);

	CURLcode ret = curl_easy_perform (curl);
	if (ret != CURLE_OK) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_FAILED, "%s", curl_easy_strerror (ret));
		curl_easy_cleanup (curl);
		return TRUE;
	}
	curl_easy_cleanup (curl);

	long response_code = 0;

	curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response_code);
	if (response_code != 200) {
		/* Cannot set *error here because that prevents NM for asking for secrets again */
		nm_connection_clear_secrets (connection);
		*setting_name = "f5vpn-session-key";
		return TRUE;
	}

	return FALSE;
}

static gboolean
nm_f5vpn_disconnect (NMVpnServicePlugin *plugin, GError **err)
{
	(void) err;

	NMF5VpnPlugin *f5vpn_plugin = NM_F5VPN_PLUGIN (plugin);
	g_assert_nonnull (f5vpn_plugin->f5vpn);

	f5vpn_disconnect (f5vpn_plugin->f5vpn);

	return TRUE;
}

void
nm_f5vpn_plugin_class_init (NMF5VpnPluginClass *klass)
{
	NMVpnServicePluginClass *parent_class = NM_VPN_SERVICE_PLUGIN_CLASS (klass);
	parent_class->connect = nm_f5vpn_connect;
	parent_class->need_secrets = nm_f5vpn_need_secrets;
	parent_class->disconnect = nm_f5vpn_disconnect;
}

void
nm_f5vpn_plugin_init (NMF5VpnPlugin *plugin)
{
	(void) plugin;
}

int
main (int argc, char **argv)
{
	NMVpnServicePlugin *plugin;
	const char *bus_name = "org.freedesktop.NetworkManager.f5vpn";
	GOptionContext *opt_ctx = NULL;
	GOptionEntry options[] = {
		{ "bus-name", 0, 0, G_OPTION_ARG_STRING, &bus_name, "D-Bus name to use for this instance", NULL },
		{ NULL }
	};
	GError *error = NULL;

	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);
	g_option_context_set_summary (opt_ctx, "nm-f5vpn-service allows NetworkManager to connect to F5 SSL VPNs.");

	g_option_context_parse (opt_ctx, &argc, &argv, NULL);
	g_option_context_free (opt_ctx);

	main_loop = g_main_loop_new (NULL, FALSE);

	plugin = g_initable_new (NM_TYPE_F5VPN_PLUGIN, NULL, &error, NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, bus_name, NULL);
	if (!plugin)
		return EXIT_FAILURE;

	g_signal_connect_swapped (plugin, "quit", G_CALLBACK (g_main_loop_quit), main_loop);
	g_main_loop_run (main_loop);

	g_main_loop_unref (main_loop);
	g_object_unref (plugin);

	return EXIT_SUCCESS;
}
