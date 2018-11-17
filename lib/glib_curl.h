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
#ifndef GLIB_CURL_H
#define GLIB_CURL_H

#include <curl/curl.h>
#include <glib.h>

struct _GlibCurl;
typedef struct _GlibCurl GlibCurl;

typedef void (*CurlCallback) (CURL *handle, void *userdata, GError *error);

GlibCurl *glib_curl_new (GMainContext *glib_context);

void glib_curl_send (GlibCurl *glc, CURL *easy, CurlCallback callback, void *userdata);

size_t curl_write_to_gstring (char *ptr, size_t size, size_t nmemb, void *userdata);

void glib_curl_free (GlibCurl *glc);

#endif // GLIB_CURL_H
