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
#include "glib_curl.h"
#include <glib-unix.h>
#include <stdint.h>

G_DEFINE_QUARK (glib - curl - error - quark, glib_curl_error)
#define GLIB_CURL_ERROR glib_curl_error_quark ()

struct _GlibCurl
{
	CURLM *multi;
	GMainContext *glib_context;
	guint timer_id;
};

typedef struct
{
	CurlCallback callback;
	void *userdata;
} CallbackData;

/* GUnixFDSource doesn't provide a public API to access the tag member,
 * and consequently a polled unix FD can't be modified. "Fix" this by
 * peeking into the ABI. Will have to be fixed if GUnixFDSource changes */
typedef struct
{
	GSource source;
	gint fd;
	gpointer tag;
} GUnixFDSource;

static void
check_multi (GlibCurl *glc)
{
	CURLMsg *msg;
	int msgs_left;
	while ((msg = curl_multi_info_read (glc->multi, &msgs_left))) {
		g_assert_true (msg->msg == CURLMSG_DONE);
		CURL *hdl = msg->easy_handle;
		CallbackData *cbd;
		curl_easy_getinfo (hdl, CURLINFO_PRIVATE, &cbd);
		curl_multi_remove_handle (glc->multi, hdl);
		GError *err = NULL;

		if (msg->data.result != CURLE_OK)
			g_error_new (GLIB_CURL_ERROR, 0, "curl error: %s", curl_easy_strerror (msg->data.result));

		(*cbd->callback) (hdl, cbd->userdata, err);
		/* Callback provider must free the curl handle */
		free (cbd);
	}
}

static gboolean
on_socket_event (gint fd, GIOCondition condition, gpointer userdata)
{
	GlibCurl *glc = (GlibCurl *) userdata;

	int ev_bitmask = 0;
	if (condition & G_IO_IN)
		ev_bitmask |= CURL_CSELECT_IN;
	if (condition & G_IO_OUT)
		ev_bitmask |= CURL_CSELECT_OUT;

	int running;
	CURLMcode rc = curl_multi_socket_action (glc->multi, fd, ev_bitmask, &running);
	if (rc != 0)
		fprintf (stderr, "error %s\n", curl_multi_strerror (rc));

	check_multi (glc);

	return TRUE;
}

static int
on_modify_socket (CURL *e, curl_socket_t s, int what, void *cbp, void *sockp)
{
	intptr_t p = (intptr_t) sockp;
	GlibCurl *glc = (GlibCurl *) cbp;

	if (what == CURL_POLL_REMOVE) {
		g_source_remove ((guint) p);
	} else {
		GIOCondition cond = 0;
		if (what & CURL_POLL_IN)
			cond |= G_IO_IN;
		if (what & CURL_POLL_OUT)
			cond |= G_IO_OUT;

		if (!p) {
			p = g_unix_fd_add (s, cond, on_socket_event, glc);
			curl_multi_assign (glc->multi, s, (void *) p);
		} else {
			GSource *src = g_main_context_find_source_by_id (glc->glib_context, (guint) p);
			GUnixFDSource *usrc = (GUnixFDSource *) src;
			g_source_modify_unix_fd (src, usrc->tag, cond);
		}
	}
	return 0;
}

static gboolean
on_timer_event (gpointer user_data)
{
	GlibCurl *glc = (GlibCurl *) user_data;
	int running = 0;
	curl_multi_socket_action (glc->multi, CURL_SOCKET_TIMEOUT, 0, &running);
	glc->timer_id = 0;

	check_multi (glc);

	return G_SOURCE_REMOVE;
}

static int
timer_callback (CURLM *multi, long timeout_ms, void *userp)
{
	GlibCurl *glc = (GlibCurl *) userp;

	if (glc->timer_id) {
		g_source_remove (glc->timer_id);
		glc->timer_id = 0;
	}

	if (timeout_ms >= 0)
		glc->timer_id = g_timeout_add (timeout_ms, on_timer_event, glc);

	return 0;
}

size_t
curl_write_to_gstring (char *ptr, size_t size, size_t nmemb, void *userdata)
{
	g_string_append_len ((GString *) userdata, ptr, size * nmemb);
	return size * nmemb;
}

void
glib_curl_send (GlibCurl *glc, CURL *easy, CurlCallback callback, void *userdata)
{
	g_assert_nonnull (glc);

	CallbackData *cbd = (CallbackData *) malloc (sizeof (CallbackData));
	cbd->callback = callback;
	cbd->userdata = userdata;

	curl_easy_setopt (easy, CURLOPT_PRIVATE, cbd);
	curl_multi_add_handle (glc->multi, easy);

	int still_running;
	CURLMcode rc = curl_multi_socket_action (glc->multi, CURL_SOCKET_TIMEOUT, 0, &still_running);
	g_assert (rc >= 0);
}

GlibCurl *
glib_curl_new (GMainContext *glib_context)
{
	GlibCurl *glc = malloc (sizeof (GlibCurl));

	glc->multi = curl_multi_init ();
	glc->glib_context = glib_context;

	curl_multi_setopt (glc->multi, CURLMOPT_SOCKETFUNCTION, on_modify_socket);
	curl_multi_setopt (glc->multi, CURLMOPT_SOCKETDATA, glc);
	curl_multi_setopt (glc->multi, CURLMOPT_TIMERFUNCTION, timer_callback);
	curl_multi_setopt (glc->multi, CURLMOPT_TIMERDATA, glc);

	return glc;
}

void
glib_curl_free (GlibCurl *glc)
{
	curl_multi_cleanup (glc->multi);
	free (glc);
}
