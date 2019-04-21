/*
 * Copyright (c) 2017 Pantacor Ltd.
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

#ifndef THTTP_H
#define THTTP_H

#include "thttp-enums.h"
#include <netinet/in.h>

#ifndef DEBUG
#define DEBUG 0
#endif

#ifndef VERBOSE
#define VERBOSE 0
#endif


typedef struct thttp_request {
	thttp_method_t method;
	thttp_proto_t proto;
	thttp_proto_version_t proto_version;

	int is_tls;

	char *host;
	int port;

	char *path;
	char **headers;

	int fd;
	int len;

	char *body;
	char *body_content_type;

	struct sockaddr conn;
} thttp_request_t;

// super struct for tls requests. ensure your thttp_request_t file
// has is_tls set.
// if you want thttp to ignore certificate problems you need to keep
// all of the Xbufs and Xfiles fields in this struct set to 0. This
// will fail if THTTP_DEVMODE environment is not set to product
// mistakes in product deployments.
typedef struct thttp_request_tls {
	thttp_request_t parent;

	// 0 terminated list of 0 terminated certificate chain bufs (multiple chains)
	char **crtbufs;
	// 0 terminated list of certificate chain files
	char **crtfiles;

	// 0 terminated list of 0 terminated CRL chain bufs (multiple chains)
	char **crlbufs;
	// 0 terminated list of certificate chain files
	char **crlfiles;

	// null terminated list of ciphersuites from mbedtls defines. if NULL
	// the reasonable defaults of mbedtls implementation will be picked.
        // -- this guy is untyped to avoid dependencies to clients on mbedtls headers
        // and 
	void *ciphersuites;
} thttp_request_tls_t;


typedef struct thttp_response {
	thttp_method_t method;
	thttp_proto_t proto;
	thttp_proto_version_t proto_version;
	char **headers;
	char *body;
	thttp_status_t code;
} thttp_response_t;


void thttp_set_log_func(int (*func)(const char *fmt, ...));

// full sync variant for http requests
thttp_response_t* thttp_request_do (thttp_request_t* req);

// save body to file instead of saving to buffer
// content-length will be set, but body will be null in response.
thttp_response_t* thttp_request_do_file (thttp_request_t *req,
					 int fd);

thttp_request_t* thttp_request_new_0 ();
thttp_request_tls_t* thttp_request_tls_new_0 ();

void thttp_request_free (thttp_request_t* ptr);
void thttp_response_free (thttp_response_t* ptr);

thttp_status_t thttp_string_to_status (char *string);
const char* thttp_status_to_string (thttp_status_t status);

thttp_proto_t thttp_string_to_proto (char *string);
const char* thttp_proto_to_string (thttp_proto_t proto);

thttp_proto_version_t thttp_string_to_proto_version (char* string);
const char* thttp_proto_version_to_string (thttp_proto_version_t proto);

thttp_method_t
thttp_string_to_method (char *string);

const char*
thttp_method_to_string (thttp_proto_t proto);

#endif // THTTP_H
