/*
 * Copyright (c) 2017-2020 Pantacor Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef TREST_H
#define TREST_H

#include "jsmn/jsmn.h"
#include "thttp.h"

typedef enum trest_auth_status {
	TREST_AUTH_STATUS_OK = 1,
	TREST_AUTH_STATUS_NOTAUTH,
	TREST_AUTH_STATUS_ERROR,
	TREST_AUTH_STATUS_UNKNOWN = 10000,
} trest_auth_status_enum;


typedef enum trest_method {
	TREST_METHOD_GET = 1,
	TREST_METHOD_POST,
	TREST_METHOD_PUT,
	TREST_METHOD_PATCH,
	TREST_METHOD_DELETE,
	TREST_METHOD_HEAD,
	TREST_METHOD_UNKNOWN = 10000,
} trest_method_enum;

typedef void* trest_ptr;
typedef void* trest_request_ptr;

typedef struct trest_response {
	trest_auth_status_enum status;

	char *body;
	char **headers;
	thttp_status_t code;

	jsmntok_t *json_tokv;
	int json_toks; // size of buffer
	int json_tokc; // count of tokens after parse

} trest_response_t;


typedef trest_response_t* trest_response_ptr;

// callback for blob messages. this gets called when
// new data is available with data pointing to the
// received data buffer and data_len having info about
// the data buffer size retrieved.
// Special conditions are treated like the following:
//  - EOF:  data == 0 && data_len == 0
//  - ERROR" data == 0 && data_len == ERROR_CODE
typedef void (*trest_cb) (void *user_data,
			  unsigned char* data,
			  size_t data_len);


trest_ptr
trest_new_from_userpass(const char* host, int port,
			const char *user,
			const char *pass,
			const char *user_agent,
			const struct sockaddr *cached);

trest_ptr
trest_new_tls_from_userpass(const char* host, int port,
			    const char *user,
			    const char *pass,
			    const char **ca_files,
			    const char *user_agent,
			    const struct sockaddr *cached);

trest_ptr
trest_new_with_login_handler(const char* host, int port,
			struct trest_response* (*login_handler) (trest_ptr self, void* data),
			void *login_data,
			const char *user_agent,
			const struct sockaddr *cached_sock);
trest_ptr
trest_new_tls_with_login_handler(const char* host, int port,
			struct trest_response* (*login_handler) (trest_ptr self, void* data),
			void *login_data,
			const char **ca_files,
			const char *user_agent,
			const struct sockaddr *cached_sock);

void
trest_set_proxy(trest_ptr c, char *host, int port, int tls);

void
trest_free (trest_ptr ptr);

void
trest_request_free (trest_request_ptr ptr);

void
trest_response_free (trest_response_ptr ptr);

// check auth status if you are just interested in this
trest_auth_status_enum
trest_auth_status (trest_ptr ptr);

// update auth tokens if possible. usually tries refresh_token
// against the login endpoint and then other credentials
// if available. usually needs to be called once to get
// initial auth token, but this behaviour depends on the
// credential type and backend implementation.
trest_auth_status_enum
trest_update_auth (trest_ptr ptr);

// make a json request; uses Encoding application/json
// and Accept-Endcoding application/json accordingly
trest_request_ptr
trest_make_request (trest_method_enum method,
		    char *endpoint_path,
		    char **queries,
		    char **headers,
		    char *json_body);


// execute the request.
// XXX: later or think about:
//   -- this will autoperform redirects
//   -- if they are going to the same service. The service
//   -- endpoint prefix is determined through a setting that
//   -- can be tweaked against the _request objects. By
//   -- default the client uses.
trest_response_ptr
trest_do_request (trest_ptr client,
		  trest_request_ptr ptr,
		  trest_cb callback,
		  void* user_data);

trest_response_ptr
trest_do_json_request (trest_ptr client,
		       trest_request_ptr);
int trest_add_headers(trest_request_ptr ptr, char **header);
int trest_add_queries(trest_request_ptr ptr, char **queries);
#endif // TREST_H
