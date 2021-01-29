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
#include "f5vpn_auth.h"
#include "glib_curl.h"

#include <libxml/HTMLparser.h>
#include <libxml/xpath.h>

G_DEFINE_QUARK (f5vpn - auth - error - quark, f5vpn_auth_error)
#define F5VPN_AUTH_ERROR f5vpn_auth_error_quark ()

#ifdef WITH_DEBUG
#define debug printf
#else
#define debug(...)
#endif

#define USER_AGENT "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"

typedef enum
{
	F5VPN_AUTH_SESSION_STATE_NEW,
	F5VPN_AUTH_SESSION_STATE_RETRIEVE_GATEWAY,
	F5VPN_AUTH_SESSION_STATE_WAITING_FOR_CREDENTIALS,
	F5VPN_AUTH_SESSION_STATE_PERFORMING_LOGIN,
	F5VPN_AUTH_SESSION_STATE_DONE,
} F5VpnAuthSessionState;

struct _F5VpnAuthSession
{
	GMainContext *glib_context;
	gchar *host;

	GlibCurl *glc;
	CURL *curl;
	GString *http_response_body;

	form_field **login_fields;
	F5VpnRequestCredentialsCallback credentials_callback;
	gpointer credentials_userdata;

	int tunnel_details_nr_pending;
	GError *err;
	GSList *tunnels_tmp;
	vpn_tunnel **tunnels;
	gchar *session_key;
	F5VpnLoginDoneCallback done_callback;
	gpointer done_userdata;

	F5VpnAuthSessionState state;
};

typedef struct
{
	CURL *curl;
	GString *http_response;
	F5VpnAuthSession *auth_session;
} TunnelDetailCtx;

static void
tunnel_detail_ctx_destroy (TunnelDetailCtx *ctx)
{
	g_string_free (ctx->http_response, TRUE);
	curl_easy_cleanup (ctx->curl);
	free (ctx);
}

static gboolean
report_login_state (gpointer user)
{
	F5VpnAuthSession *session = (F5VpnAuthSession *) user;

	debug ("report_login_state\n");
	(session->done_callback) (session, session->session_key, (const vpn_tunnel *const *) session->tunnels, session->done_userdata, session->err);
	session->err = NULL;

	return G_SOURCE_REMOVE;
}

static void
handle_tunnel_detail_error (F5VpnAuthSession *session, GError *err)
{
	if (session->err) {
		/* we already have an error, discard this one */
		g_error_free (err);
	} else {
		session->err = err;
	}

	if (session->tunnel_details_nr_pending == 0) {
		/* no more pending requests, propagate the error */
		g_timeout_add (0, report_login_state, session);
	}
}

static void
on_tunnel_detail_response (CURL *curl, void *user, GError *err)
{
	TunnelDetailCtx *ctx = (TunnelDetailCtx *) user;
	F5VpnAuthSession *session = ctx->auth_session;
	long response_code = 0;
	xmlDoc *doc;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	gchar *res_id = NULL, *res_caption = NULL, *res_description = NULL;
	gboolean res_autolaunch = FALSE;

	session->tunnel_details_nr_pending--;
	/* since we may have multiple requests, wait for all of them before reporting any error */

	g_assert_true (session->state == F5VPN_AUTH_SESSION_STATE_PERFORMING_LOGIN);

	if (err) {
		tunnel_detail_ctx_destroy (ctx);
		handle_tunnel_detail_error (session, err);
		return;
	}

	curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response_code);
	if (response_code != 200) {
		char *url;
		curl_easy_getinfo (curl, CURLINFO_EFFECTIVE_URL, &url);
		err = g_error_new (F5VPN_AUTH_ERROR, 0, "Unexpected HTTP response code %lu received from %s", response_code, url);
		tunnel_detail_ctx_destroy (ctx);
		handle_tunnel_detail_error (session, err);
		return;
	}

	doc = xmlParseMemory (ctx->http_response->str, ctx->http_response->len);
	if (doc == NULL) {
		err = g_error_new (F5VPN_AUTH_ERROR, 0, "Could not parse server response XML: %s", ctx->http_response->str);
		tunnel_detail_ctx_destroy (ctx);
		handle_tunnel_detail_error (session, err);
		return;
	}

	xpathCtx = xmlXPathNewContext (doc);
	xpathObj = xmlXPathEvalExpression ("string(/resources/item/id)", xpathCtx);
	if (xpathObj && xpathObj->stringval)
		res_id = strdup (xpathObj->stringval);
	xmlXPathFreeObject (xpathObj);

	xpathObj = xmlXPathEvalExpression ("string(/resources/item/caption)", xpathCtx);
	if (xpathObj && xpathObj->stringval)
		res_caption = strdup (xpathObj->stringval);
	xmlXPathFreeObject (xpathObj);

	xpathObj = xmlXPathEvalExpression ("string(/resources/item/description)", xpathCtx);
	if (xpathObj && xpathObj->stringval)
		res_description = strdup (xpathObj->stringval);
	xmlXPathFreeObject (xpathObj);

	xpathObj = xmlXPathEvalExpression ("string(/resources/item/autolaunch)", xpathCtx);
	if (xpathObj && xpathObj->stringval)
		res_autolaunch = *xpathObj->stringval == '1';
	xmlXPathFreeObject (xpathObj);

	xmlXPathFreeContext (xpathCtx);
	xmlFreeDoc (doc);

	if (!(res_id && res_caption && res_description)) {
		err = g_error_new (F5VPN_AUTH_ERROR, 0, "Expected field missing in tunnel detail XML: %s", ctx->http_response->str);
		free (res_id);
		free (res_caption);
		free (res_description);
		tunnel_detail_ctx_destroy (ctx);
		handle_tunnel_detail_error (session, err);
		return;
	}

	tunnel_detail_ctx_destroy (ctx);

	vpn_tunnel *detail = calloc (1, sizeof (vpn_tunnel));
	detail->id = res_id;
	detail->label = res_caption;
	detail->description = res_description;
	detail->autoconnect = res_autolaunch;
	session->tunnels_tmp = g_slist_append (session->tunnels_tmp, detail);

	/* henceforth simpler error handling, we won't be here simultaneously */
	if (session->tunnel_details_nr_pending > 0)
		return;

	/* convert list to pointer array */
	int i = 0;
	session->tunnels = calloc (g_slist_length (session->tunnels_tmp) + 1, sizeof (vpn_tunnel *));
	for (GSList *p = session->tunnels_tmp; p; p = p->next)
		session->tunnels[i] = p->data;
	g_slist_free (session->tunnels_tmp);
	session->tunnels_tmp = NULL;

	/* retrieve the session key from the curl handle */
	struct curl_slist *cookies;
	curl_easy_getinfo (session->curl, CURLINFO_COOKIELIST, &cookies);
	char cookie_key[32] = { 0 }, cookie_value[64] = { 0 };
	for (struct curl_slist *p = cookies; p; p = p->next) {
		sscanf (p->data, "%*s\t%*s\t%*s\t%*s\t%*s\t%31s\t%63s", cookie_key, cookie_value);
		if (strcmp (cookie_key, "MRHSession") == 0) {
			session->session_key = strdup (cookie_value);
			break;
		}
	}
	curl_slist_free_all (cookies);

	if (!session->session_key) {
		session->err = g_error_new (F5VPN_AUTH_ERROR, 0, "Could not retrieve session key from curl handle");
	}

	/* invoke user callback */
	session->state = F5VPN_AUTH_SESSION_STATE_DONE;
	g_timeout_add (0, report_login_state, session);
}

static CURL *
f5vpn_curl_new (void)
{
	CURL *curl = curl_easy_init ();
	curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt (curl, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt (curl, CURLOPT_COOKIEFILE, "");
	curl_easy_setopt (curl, CURLOPT_USERAGENT, USER_AGENT);
	curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, curl_write_to_gstring);
	return curl;
}

static void
on_resource_list_retrieved (CURL *curl, void *user, GError *err)
{
	F5VpnAuthSession *session = (F5VpnAuthSession *) user;
	long response_code;
	xmlDoc *doc;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	gchar *detail_uri = NULL;

	g_assert_true (session->state == F5VPN_AUTH_SESSION_STATE_PERFORMING_LOGIN);

	if (err) {
		session->err = err;
		g_timeout_add (0, report_login_state, session);
		return;
	}

	curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response_code);
	if (response_code != 200) {
		char *url;
		curl_easy_getinfo (curl, CURLINFO_EFFECTIVE_URL, &url);
		session->err = g_error_new (F5VPN_AUTH_ERROR, 0, "Unexpected HTTP response code %lu received from %s", response_code, url);
		g_timeout_add (0, report_login_state, session);
		return;
	}

	debug ("%.*s\n", (int) session->http_response_body->len, session->http_response_body->str);

	doc = xmlParseMemory (session->http_response_body->str, session->http_response_body->len);
	if (doc == NULL) {
		session->err = g_error_new (F5VPN_AUTH_ERROR, 0, "Could not parse server response XML: %s", session->http_response_body->str);
		g_timeout_add (0, report_login_state, session);
		return;
	}

	xpathCtx = xmlXPathNewContext (doc);

	xpathObj = xmlXPathEvalExpression ("string(/res[@type='resource_list']/opts/opt[@type='available_rq']/@uri)", xpathCtx);
	if (xpathObj && xpathObj->stringval)
		detail_uri = strdup (xpathObj->stringval);
	xmlXPathFreeObject (xpathObj);

	if (!detail_uri) {
		xmlXPathFreeContext (xpathCtx);
		xmlFreeDoc (doc);
		session->err = g_error_new (F5VPN_AUTH_ERROR, 0, "Could not retrieve detail URI from server response XML: %s", session->http_response_body->str);
		g_timeout_add (0, report_login_state, session);
		return;
	}

	xpathObj = xmlXPathEvalExpression ("/res[@type='resource_list']/lists/list[@type='network_access']/entry", xpathCtx);

	if (!xpathObj || !xpathObj->nodesetval) {
		free (detail_uri);
		xmlXPathFreeObject (xpathObj);
		xmlXPathFreeContext (xpathCtx);
		xmlFreeDoc (doc);
		session->err = g_error_new (F5VPN_AUTH_ERROR, 0, "Could not retrieve vpn entry from server response XML: %s", session->http_response_body->str);
		g_timeout_add (0, report_login_state, session);
		return;
	}

	session->tunnel_details_nr_pending = 0;
	for (int i = 0; i < xpathObj->nodesetval->nodeNr; ++i) {
		xmlNode *node = xpathObj->nodesetval->nodeTab[i];
		for (xmlAttr *a = node->properties; a; a = a->next) {
			if (strcmp (a->name, "param") == 0) {
				TunnelDetailCtx *ctx = calloc (1, sizeof (TunnelDetailCtx));

				ctx->auth_session = session;
				ctx->http_response = g_string_new ("");
				ctx->curl = f5vpn_curl_new ();

				curl_easy_setopt (ctx->curl, CURLOPT_WRITEDATA, ctx->http_response);
				curl_easy_setopt (ctx->curl, CURLOPT_VERBOSE, 1L);

				char *uri = g_strdup_printf ("https://%s%s?%s=%s", session->host, detail_uri, a->children->content, node->children->content);
				debug ("request tunnel info at [%s]\n", uri);
				curl_easy_setopt (ctx->curl, CURLOPT_URL, uri);
				free (uri);

				/* Copy cookies to the new handle */
				struct curl_slist *cookies;
				curl_easy_getinfo (curl, CURLINFO_COOKIELIST, &cookies);
				for (struct curl_slist *p = cookies; p; p = p->next)
					curl_easy_setopt (ctx->curl, CURLOPT_COOKIELIST, p->data);
				curl_slist_free_all (cookies);

				session->tunnel_details_nr_pending++;
				glib_curl_send (session->glc, ctx->curl, on_tunnel_detail_response, ctx);

				break;
			}
		}
	}
	xmlXPathFreeObject (xpathObj);

	xmlXPathFreeContext (xpathCtx);
	xmlFreeDoc (doc);
	free (detail_uri);

	if (session->tunnel_details_nr_pending == 0) {
		session->err = g_error_new (F5VPN_AUTH_ERROR, 0, "No valid tunnel descriptions found in server XML: %s", session->http_response_body->str);
		g_timeout_add (0, report_login_state, session);
	}
}

static void
on_epi_skip_response (CURL *curl, void *user, GError *err)
{
	F5VpnAuthSession *session;
	long response_code;
	gchar *url;

	session = (F5VpnAuthSession *) user;
	g_assert_true (session->state == F5VPN_AUTH_SESSION_STATE_PERFORMING_LOGIN);

	if (err) {
		session->err = err;
		g_timeout_add (0, report_login_state, session);
		return;
	}

	curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response_code);
	if (response_code != 302) {
		curl_easy_getinfo (curl, CURLINFO_EFFECTIVE_URL, &url);
		session->err = g_error_new (F5VPN_AUTH_ERROR, 0, "Unexpected HTTP response code %lu received from %s", response_code, url);
		g_timeout_add (0, report_login_state, session);
		return;
	}

	/* Last request was a POST, so reset the handle back to a GET */
	curl_easy_setopt (session->curl, CURLOPT_HTTPGET, 1L);
	/* URL appears to be hard-coded */
	url = g_strdup_printf ("https://%s/vdesk/resource_list.xml?resourcetype=res", session->host);
	curl_easy_setopt (session->curl, CURLOPT_URL, url);
	g_free (url);

	glib_curl_send (session->glc, session->curl, on_resource_list_retrieved, session);
}

static void
on_login_result (CURL *curl, void *user, GError *err)
{
	F5VpnAuthSession *session;
	long response_code;
	gchar *url;

	session = (F5VpnAuthSession *) user;
	g_assert_true (session->state == F5VPN_AUTH_SESSION_STATE_PERFORMING_LOGIN);

	if (err) {
		session->err = err;
		g_timeout_add (0, report_login_state, session);
		return;
	}

	curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response_code);
	/* Some servers respond 200, some 302 */
	if (!(response_code == 302 || response_code == 200)) {
		curl_easy_getinfo (curl, CURLINFO_EFFECTIVE_URL, &url);
		session->err = g_error_new (F5VPN_AUTH_ERROR, 0, "Unexpected HTTP response code %lu received from %s", response_code, url);
		g_timeout_add (0, report_login_state, session);
		return;
	}

	/* If credentials were rejected, the response is still 200 :(
	 * In this case, try to parse the pretty error message out of the HTML body.
	 * TODO: proper HTML parsing? */
	if (strstr (session->http_response_body->str, "class=\"logon_page\"")) {
		char *p;
		if ((p = strstr (session->http_response_body->str, "credentials_table_postheader"))) {
			*strstr (p, "</") = '\0';
			session->err = g_error_new (F5VPN_AUTH_ERROR, 0, "%s", rindex (p, '>') + 1);
		} else {
			session->err = g_error_new (F5VPN_AUTH_ERROR, 0, "Unexpected recurrence of logon page");
		}
		g_timeout_add (0, report_login_state, session);
		return;
	}

	g_string_truncate (session->http_response_body, 0);

	/* Some servers have EPI. Don't know how to do that, but apparently you can skip it by sending a special POST */
	curl_easy_setopt (session->curl, CURLOPT_POSTFIELDS, "no-inspection-host=1");
	url = g_strdup_printf ("https://%s/my.policy", session->host);
	curl_easy_setopt (session->curl, CURLOPT_URL, url);
	g_free (url);

	glib_curl_send (session->glc, session->curl, on_epi_skip_response, session);
}

void
f5vpn_auth_session_post_credentials (F5VpnAuthSession *session, F5VpnLoginDoneCallback callback, void *userdata)
{
	char *postdata, *redirect_url = NULL;
	const char *sep;

	g_assert_true (session->state == F5VPN_AUTH_SESSION_STATE_WAITING_FOR_CREDENTIALS);

	g_string_truncate (session->http_response_body, 0);

	session->done_callback = callback;
	session->done_userdata = userdata;

	/* Lots of extraneous mallocs....lalallala */
	postdata = strdup ("");
	sep = "";
	for (form_field **f = session->login_fields; *f; ++f) {
		char *escaped_value, *old_postdata;
		form_field *field = *f;

		if (field->type == FORM_FIELD_OTHER)
			continue;

		escaped_value = g_uri_escape_string (field->value, NULL, FALSE);
		old_postdata = postdata;
		postdata = g_strdup_printf ("%s%s%s=%s", old_postdata, sep, field->name, escaped_value);
		free (old_postdata);
		free (escaped_value);
		sep = "&";
	}

	curl_easy_getinfo (session->curl, CURLINFO_EFFECTIVE_URL, &redirect_url);
	if (redirect_url) {
		curl_easy_setopt (session->curl, CURLOPT_URL, g_strdup (redirect_url));
	}

	curl_easy_setopt (session->curl, CURLOPT_FOLLOWLOCATION, 0L);
	/* Allows us to free postdata */
	curl_easy_setopt (session->curl, CURLOPT_COPYPOSTFIELDS, postdata);
	free (postdata);

	session->state = F5VPN_AUTH_SESSION_STATE_PERFORMING_LOGIN;
	glib_curl_send (session->glc, session->curl, on_login_result, session);
}

#define MAX_LOGIN_FIELDS 5
typedef struct
{
	gboolean in_form;
	gboolean in_label;
	form_field *fields[MAX_LOGIN_FIELDS];
	int field_idx;
	int label_idx;
	char *last_label;
} html_parse_ctx;

static void
parse_login_page_cb_start_element (html_parse_ctx *ctx, const xmlChar *name, const xmlChar **atts)
{
	if (ctx->in_form) {
		if (strcmp (name, "label") == 0) {
			g_assert_false (ctx->in_label);
			ctx->in_label = TRUE;
		} else if (strcmp (name, "input") == 0) {
			ctx->fields[ctx->field_idx] = calloc (sizeof (form_field), 1);
			for (const xmlChar **p = atts; p && *p; p++) {
				if (strcmp (*p, "name") == 0 && p[1]) {
					ctx->fields[ctx->field_idx]->name = strdup (p[1]);
					p++;
				} else if (strcmp (*p, "type") == 0 && p[1]) {
					ctx->fields[ctx->field_idx]->type =
					    (strcmp (p[1], "text") == 0)
					        ? FORM_FIELD_TEXT
					        : (strcmp (p[1], "password") == 0)
					              ? FORM_FIELD_PASSWORD
					              : (strcmp (p[1], "hidden") == 0) ? FORM_FIELD_HIDDEN
					                                               : FORM_FIELD_OTHER;
					p++;
				} else if (strcmp (*p, "value") == 0 && p[1]) {
					ctx->fields[ctx->field_idx]->value = strdup (p[1]);
					p++;
				}
			}
			if (ctx->last_label) {
				ctx->fields[ctx->field_idx]->label = ctx->last_label;
				ctx->last_label = NULL;
			} else if (ctx->fields[ctx->field_idx]->name) {
				ctx->fields[ctx->field_idx]->label =
				    strdup (ctx->fields[ctx->field_idx]->name);
			}
		}
	} else if (strcmp (name, "form") == 0) {
		for (const xmlChar **p = atts; p && *p; p++) {
			if (strcmp (*p, "id") == 0 && p[1] && strcmp (p[1], "auth_form") == 0) {
				ctx->in_form = TRUE;
				break;
			}
		}
	}
}

static void
parse_login_page_cb_characters (html_parse_ctx *ctx, const xmlChar *ch, int len)
{
	if (ctx->in_label)
		ctx->last_label = strndup (ch, len);
}

static void
parse_login_page_cb_end_element (html_parse_ctx *ctx, const xmlChar *name)
{
	if (!ctx->in_form)
		return;

	if (strcmp (name, "form") == 0) {
		ctx->in_form = FALSE;
	} else if (strcmp (name, "label") == 0) {
		g_assert_true (ctx->in_label);
		ctx->in_label = FALSE;
	} else if (strcmp (name, "input") == 0) {
		ctx->field_idx++;
	}
}

static gboolean
report_auth_state (gpointer user)
{
	F5VpnAuthSession *session = (F5VpnAuthSession *) user;
	(session->credentials_callback) (session, session->login_fields, session->credentials_userdata, session->err);
	session->err = NULL;
	return G_SOURCE_REMOVE;
}

static void
on_auth_portal_reached (CURL *curl, void *user, GError *err)
{
	F5VpnAuthSession *session;
	long response_code;

	session = (F5VpnAuthSession *) user;
	g_assert_true (session->state == F5VPN_AUTH_SESSION_STATE_RETRIEVE_GATEWAY);

	if (err) {
		session->err = err;
		g_timeout_add (0, report_auth_state, session);
		return;
	}

	curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response_code);
	if (response_code != 200) {
		char *url;
		session->state = F5VPN_AUTH_SESSION_STATE_DONE;
		curl_easy_getinfo (curl, CURLINFO_EFFECTIVE_URL, &url);
		session->err = g_error_new (F5VPN_AUTH_ERROR, 0, "Unexpected HTTP response code %lu received from %s", response_code, url);
		g_timeout_add (0, report_auth_state, session);
		return;
	}

	html_parse_ctx ctx = {
		.in_form = FALSE,
		.field_idx = 0,
		.label_idx = 0,
		.last_label = NULL,
	};
	static xmlSAXHandler sax_parse_handlers = {
		.startElement = (startElementSAXFunc) parse_login_page_cb_start_element,
		.characters = (charactersSAXFunc) parse_login_page_cb_characters,
		.endElement = (endElementSAXFunc) parse_login_page_cb_end_element,
	};
	htmlSAXParseDoc ((const xmlChar *) session->http_response_body->str, "utf-8", &sax_parse_handlers, &ctx);

	session->login_fields = calloc (sizeof (form_field *), ctx.field_idx + 1);
	for (int i = 0; i < ctx.field_idx; ++i)
		session->login_fields[i] = ctx.fields[i];

	session->state = F5VPN_AUTH_SESSION_STATE_WAITING_FOR_CREDENTIALS;
	g_timeout_add (0, report_auth_state, session);
}

void
f5vpn_auth_session_begin (F5VpnAuthSession *session, F5VpnRequestCredentialsCallback callback, void *userdata)
{
	gchar *url;

	g_assert_true (session->state == F5VPN_AUTH_SESSION_STATE_NEW);
	session->credentials_callback = callback;
	session->credentials_userdata = userdata;

	/* For the first request, allow redirection */
	curl_easy_setopt (session->curl, CURLOPT_FOLLOWLOCATION, 1L);

	url = g_strdup_printf ("https://%s", session->host);
	curl_easy_setopt (session->curl, CURLOPT_URL, url);
	g_free (url);

	session->state = F5VPN_AUTH_SESSION_STATE_RETRIEVE_GATEWAY;
	glib_curl_send (session->glc, session->curl, on_auth_portal_reached, session);
}

F5VpnAuthSession *
f5vpn_auth_session_new (GMainContext *glib_context, const char *host)
{
	F5VpnAuthSession *session = malloc (sizeof (F5VpnAuthSession));
	session->glib_context = glib_context;
	session->glc = glib_curl_new (glib_context);
	session->host = strdup (host);
	session->state = F5VPN_AUTH_SESSION_STATE_NEW;
	session->http_response_body = g_string_new ("");
	session->login_fields = NULL;
	session->tunnels = NULL;
	session->err = NULL;
	session->tunnels_tmp = NULL;
	session->tunnel_details_nr_pending = 0;
	session->session_key = NULL;

	session->curl = f5vpn_curl_new ();
	curl_easy_setopt (session->curl, CURLOPT_WRITEDATA, session->http_response_body);

	return session;
}

void
f5vpn_auth_session_free (F5VpnAuthSession *session)
{
	free (session->host);
	curl_easy_cleanup (session->curl);
	glib_curl_free (session->glc);
	g_string_free (session->http_response_body, TRUE);
	if (session->login_fields) {
		for (form_field **p = session->login_fields; *p; ++p) {
			free ((*p)->label);
			free ((*p)->name);
			free ((*p)->value);
			free (*p);
		}
		free (session->login_fields);
	}
	g_slist_free_full (session->tunnels_tmp, free);
	if (session->tunnels) {
		for (vpn_tunnel **t = session->tunnels; *t; ++t) {
			free ((*t)->id);
			free ((*t)->label);
			free ((*t)->description);
			free (*t);
		}
		free (session->tunnels);
	}
	free (session->session_key);
	free (session);
}
