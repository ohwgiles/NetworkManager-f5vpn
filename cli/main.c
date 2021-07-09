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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include <stdio.h>
#include <glib.h>
#include <termios.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "f5vpn_auth.h"
#include "f5vpn_getsid.h"
#include "f5vpn_connect.h"

typedef struct {
	GMainLoop* main_loop;
	const char* hostname;
	gboolean do_connect;
	const char* vpn_z_id;
} F5VpnCli;

static void handle_connection_status(F5VpnConnection *connection, const NetworkSettings *settings, void *userdata, GError *err)
{
	F5VpnCli *cli = (F5VpnCli*) userdata;
	if(err) {
		fprintf(stderr, "error: %s\n", err->message);
		if(err->code == F5VPN_CONNECT_ERROR_BAD_HTTP_CODE) {
			fprintf(stderr, "session key should be invalidated\n");
		}
		g_error_free(err);
		f5vpn_connection_free(connection);
		g_main_loop_quit(cli->main_loop);
		return;
	}

	if (!settings) {
		/* connection gone down */
		fprintf(stderr, "connection closed\n");
		f5vpn_connection_free(connection);
		g_main_loop_quit(cli->main_loop);
		return;
	}

	/* connection up! */
	printf("connection up!\n");
	char str_peer[INET_ADDRSTRLEN] = "";
	inet_ntop(AF_INET, &settings->remote_ip, str_peer, INET_ADDRSTRLEN);
	for (GSList *p = settings->lans; p; p = p->next) {
		char str_route[INET_ADDRSTRLEN] = "";
		inet_ntop(AF_INET, &((LanAddr*) p->data)->addr, str_route, INET_ADDRSTRLEN);
		printf("ip route add %s/%d via %s dev %s\n", str_route, ((LanAddr*) p->data)->mask, str_peer, settings->device);
	}
	for (GSList *p = settings->nameservers; p; p = p->next) {
		char str_dns[INET_ADDRSTRLEN] = "";
		inet_ntop(AF_INET, p->data, str_dns, INET_ADDRSTRLEN);
		printf("resolvconf %s\n", str_dns);
	}
}

static void on_login_done(F5VpnAuthSession* session, const char* session_key, const vpn_tunnel* const* vpn_ids, void *userdata, GError* err)
{
	(void) session;

	F5VpnCli *cli = (F5VpnCli*) userdata;
	static char buffer[4] = "";
	int chosen_tunnel = 0;

	if(err) {
		fprintf(stderr, "error: %s\n", err->message);
		g_error_free(err);
		g_main_loop_quit(cli->main_loop);
		return;
	}

	printf("session key: %s\n", session_key);

	if(!cli->do_connect) {
		for(const vpn_tunnel* const* p = vpn_ids; *p; ++p) {
			printf("tunnel: %s (%s)\n", (*p)->id, (*p)->label);
		}
		g_main_loop_quit(cli->main_loop);
		return;
	}

	/* do_connect == TRUE */
	int n = 1;
	for(const vpn_tunnel* const* p = vpn_ids; *p; ++p) {
		printf("%d) %s %s\n", n++, (*p)->label, (*p)->description);
	}
	do {
		printf("Select a tunnel: ");
		if(fgets(buffer, 3, stdin) == NULL) {
			g_main_loop_quit(cli->main_loop);
			return;
		}
		chosen_tunnel = atoi(buffer);
	} while(chosen_tunnel < 1 || chosen_tunnel >= n);

	f5vpn_connect(g_main_loop_get_context(cli->main_loop), cli->hostname, session_key, vpn_ids[chosen_tunnel - 1]->id, handle_connection_status, cli);
}

static char* user_get_text(void)
{
	static char buffer[128];
	if(fgets(buffer, 127, stdin) == NULL)
		return NULL;
	*strchrnul(buffer, '\n') = '\0';
	return strdup(buffer);
}

static char* user_get_password(void)
{
	struct termios term_old, term_new;
	tcgetattr(STDIN_FILENO, &term_old);

	term_new = term_old;
	term_new.c_lflag &= ~ECHO;

	tcsetattr(STDIN_FILENO, TCSANOW, &term_new);
	char* result = user_get_text();
	tcsetattr(STDIN_FILENO, TCSANOW, &term_old);

	printf("\n");

	return result;
}

static void on_credentials_needed(F5VpnAuthSession* session, form_field *const*fields, void *userdata, GError* err)
{
	F5VpnCli *cli = (F5VpnCli*) userdata;

	if(err) {
		fprintf(stderr, "error: %s\n", err->message);
		g_error_free(err);
		g_main_loop_quit(cli->main_loop);
		return;
	}

	for(form_field *const*f = fields; *f; ++f) {
		form_field *field = *f;
		if(field->type == FORM_FIELD_TEXT) {
			printf("%s: ", field->label);
			free(field->value);
			field->value = user_get_text();
		} else if(field->type == FORM_FIELD_PASSWORD) {
			printf("%s: ", field->label);
			free(field->value);
			field->value = user_get_password();
		}
	}

	f5vpn_auth_session_post_credentials(session, on_login_done, cli);
}

static void on_otc_retrieved(F5VpnGetSid *getsid, const char *session_key, void *userdata, GError* err)
{
	(void) getsid;

	F5VpnCli *cli = (F5VpnCli*) userdata;

	if(err) {
		fprintf(stderr, "error: %s\n", err->message);
		g_error_free(err);
		g_main_loop_quit(cli->main_loop);
		return;
	}

	printf("session key: %s\n", session_key);

	if(cli->do_connect) {
		f5vpn_connect(g_main_loop_get_context(cli->main_loop), cli->hostname, session_key, cli->vpn_z_id, handle_connection_status, cli);
	} else {
		g_main_loop_quit(cli->main_loop);
	}

}

int main(int argc, char** argv)
{
	F5VpnCli cli = {0};
	gboolean do_auth = FALSE, do_getsid = FALSE;
	gchar *session_key = NULL, *otc = NULL;
	GOptionContext *opt_ctx = NULL;
	F5VpnAuthSession *auth = NULL;
	F5VpnGetSid *getsid = NULL;
	
	GOptionEntry options[] = {
	    { "auth", 'a', 0, G_OPTION_ARG_NONE, &do_auth, "Authenticate to obtain a session key", NULL },
	    { "getsid", 'g', 0, G_OPTION_ARG_NONE, &do_getsid, "Exchange a One-Time-Code for a session key", NULL },
	    { "connect", 'c', 0, G_OPTION_ARG_NONE, &cli.do_connect, "Connect to remote VPN", NULL },
	    { "session", 's', 0, G_OPTION_ARG_STRING, &session_key, "Provide a session key", NULL },
	    { "otc", 'o', 0, G_OPTION_ARG_STRING, &otc, "Provide a One-Time-Code", NULL },
	    { "host", 'h', 0, G_OPTION_ARG_STRING, &cli.hostname, "F5 SSL VPN host", NULL },
	    { "vpn-z-id", 'z', 0, G_OPTION_ARG_STRING, &cli.vpn_z_id, "VPN id to use", NULL },
	    { NULL }
	};
	
	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);	
	g_option_context_set_summary (opt_ctx, "Connect to F5 SSL VPNs.");
	g_option_context_parse (opt_ctx, &argc, &argv, NULL);
	g_option_context_free (opt_ctx);
	
	if (!cli.hostname)
		return fprintf(stderr, "hostname must be provided\n"), EXIT_FAILURE;
	
	if (do_auth && do_getsid)
		return fprintf(stderr, "--auth conflicts with --getsid\n"), EXIT_FAILURE;

	if (do_getsid && !otc)
		return fprintf(stderr, "otc must be provided when exchanging otc for session key\n"), EXIT_FAILURE;

	if (do_getsid && session_key)
		return fprintf(stderr, "session key should not be provided when exchanging otc for session key\n"), EXIT_FAILURE;

	if (do_getsid && !cli.do_connect && cli.vpn_z_id)
		return fprintf(stderr, "not connecting: vpn_z_id should not be provided\n"), EXIT_FAILURE;

	if (do_auth && (session_key || otc || cli.vpn_z_id))
		return fprintf(stderr, "neither session_key, otc nor vpn_z_id should be provided when authenticating\n"), EXIT_FAILURE;
	
	if (cli.do_connect && !do_auth && (!cli.vpn_z_id || (!session_key && !do_getsid)))
		return fprintf(stderr, "not authenticating: session key (or otc) and Z-id must be provided\n"), EXIT_FAILURE;

	if (!do_auth && !do_getsid && !cli.do_connect)
		return fprintf(stderr, "one or more of --auth, --getsid or --connect must be used\n"), EXIT_FAILURE;

	cli.main_loop = g_main_loop_new(NULL, FALSE);

	if (do_auth) {
		auth = f5vpn_auth_session_new(g_main_loop_get_context(cli.main_loop), cli.hostname);
		f5vpn_auth_session_begin(auth, on_credentials_needed, &cli);
	} else if (do_getsid) {
		getsid = f5vpn_getsid_begin(g_main_loop_get_context(cli.main_loop), cli.hostname, otc, on_otc_retrieved, &cli);
	} else if(cli.do_connect) {
		f5vpn_connect(g_main_loop_get_context(cli.main_loop), cli.hostname, session_key, cli.vpn_z_id, handle_connection_status, &cli);
	}

	g_main_loop_run(cli.main_loop);

	if (auth) {
		f5vpn_auth_session_free(auth);
	}

	if (getsid) {
		f5vpn_getsid_free(getsid);
	}

	g_main_loop_unref(cli.main_loop);

	return 0;
}
