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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jsmn/jsmnutil.h"
#include "jsmn/jsmn.h"
#include "trest.h"

#include <netinet/in.h>
#include <stdbool.h>

enum trest_rtype {
	trest_rtype_JSON =1,
	trest_rtype_BLOB,
};

enum trest_auth_type {
	trest_auth_type_BASIC=0,
	trest_auth_type_DAUTH,
	trest_auth_type_UNKNOWN=10000
};

enum trest_req_alloc_type {
	TREST_ALLOC_HEADER,
	TREST_ALLOC_QUERY,
	TREST_ALLOC_UNKNOWN
};


struct trest {
	enum trest_auth_type type;
	trest_auth_status_enum status;

	char *host;
	int port;

	char **credentials;
	char *access_token;
	char *refresh_token;

	const char *user_agent;

	int is_tls;
	char **tls_cafiles;
	struct sockaddr conn;

	// we allow third party handlers for login to be implemented
	struct trest_response* (*login_handler) (trest_ptr self, void* data);
	void *login_data;
};

struct trest_request {
	enum trest_rtype type;
	thttp_method_t method;

	char *endpoint_path;
	char **queries;
	char **headers;
	char *json_body;
	int nr_queries;
	int nr_headers;
	void (*on_free)(struct trest_request*);
};

static void
update_tokens_from_json_response (struct trest *self,
				  struct trest_response *response)
{
	// if we got a response parse it
	jsmntok_t *jv;
	int c,i,t=-1;
	char *body;

	jv = response->json_tokv;
	c = response->json_tokc;
	body = response->body;

	if (DEBUG)
		printf ("update_tokens_from_json_response: %s\n", body);

	for (i=0; i<c && t != 0; i++) {
		int n = jv[i].end - jv[i].start;
		char *token = malloc(n+1);
		strncpy(token, body + jv[i].start, n);
		token[n]=0;

		if (jv[i].type == JSMN_STRING
		    && !strncmp(body + jv[i].start, "token", 5)) {
			t=1;
		} else if (t==1 && jv[i].type == JSMN_STRING) {
			token[n] = 0;
			strncpy(token, body + jv[i].start, n);
			if (self->access_token)
				free(self->access_token);
			self->access_token = strdup(token);

			if (self->refresh_token)
				free(self->refresh_token);
			self->refresh_token = strdup (token);
		} else if (t==1) {
			t=0;
		}
		free(token);
	}
	if (DEBUG && self->access_token)
		printf("New access token: %s\n", self->access_token);
	if (DEBUG && self->refresh_token)
		printf("New refresh token: %s\n", self->access_token);
}

static trest_auth_status_enum
do_refresh_login (struct trest *self)
{
	// for start lets clear access_token if set
	if (self->access_token) {
		return self->status;
	}
	else {
		self->status = TREST_AUTH_STATUS_NOTAUTH;
	}
	return self->status;
}

static struct trest_response*
do_credentials_login_userpass (trest_ptr client, void *cb_data)
{
	trest_response_ptr r;
	trest_request_ptr p;
	struct trest *self = client;

	const char* userpass =
		"{ \"username\": \"%s\""
		", \"password\": \"%s\" }";

	char *b = malloc (sizeof(char) *
			  (strlen(userpass)
			   + strlen(self->credentials[0])
			   + strlen(self->credentials[1])));

	sprintf(b, userpass, self->credentials[0], self->credentials[1]);

	if (DEBUG)
		printf ("do_credentials_login with body : %s\n", b);

	p = trest_make_request (TREST_METHOD_POST,
				"/auth/login",
				NULL,
				NULL,
				b);
	free (b);

	r = trest_do_json_request (self, p);

	if (DEBUG)
		printf ("do_credentials_login code: %d\n", r->code);
exit:
	trest_request_free(p);
	return r;
}

static trest_auth_status_enum
do_credentials_login (struct trest *self)
{
	struct trest_response* response =
	       self->login_handler(self, self->login_data);

	if (response->code == THTTP_STATUS_UNAUTHORIZED) {
		self->status = TREST_AUTH_STATUS_NOTAUTH;
		goto exit;
	} else if (response->code != THTTP_STATUS_OK) {
		self->status = TREST_AUTH_STATUS_ERROR;
		goto exit;
	}
	update_tokens_from_json_response (self, response);
	self->status = TREST_AUTH_STATUS_OK;

exit:
	trest_response_free(response);
	return self->status;
}

trest_ptr
trest_new_with_login_handler(const char* host, int port,
			struct trest_response* (*login_handler) (trest_ptr self, void* data),
			void *login_data,
			const char *user_agent,
			const struct sockaddr *cached_sock)
{
	struct trest* client =
		calloc (sizeof(struct trest), 1);

	client->host = strdup(host);
	client->port = port;
	client->type = trest_auth_type_BASIC;
	client->user_agent = user_agent;
	client->status = TREST_AUTH_STATUS_NOTAUTH;

	client->credentials = NULL;

	if (cached_sock)
		memcpy(&client->conn, cached_sock, sizeof(*cached_sock));

	client->login_handler = login_handler;
	client->login_data = login_data;

	return (trest_ptr) client;
}

trest_ptr
trest_new_from_userpass(const char* host, int port,
			const char *user,
			const char *pass,
			const char *user_agent,
			const struct sockaddr *cached_sock)
{
	struct trest* client = trest_new_with_login_handler (
			host,
			port,
			do_credentials_login_userpass,
			NULL,
			user_agent,
			cached_sock);

	client->credentials = malloc(sizeof(char*) * 3);
	client->credentials[0] = strdup(user);
	client->credentials[1] = strdup(pass);
	client->credentials[2] = (char*) 0;

	return (trest_ptr) client;
}

trest_ptr
trest_new_tls_with_login_handler(const char* host, int port,
			struct trest_response* (*login_handler) (trest_ptr self, void* data),
		 	void *login_data,
			const char **cafiles,
			const char *user_agent,
			const struct sockaddr *cached_sock)

{
	struct trest* client = (struct trest*)
		trest_new_with_login_handler(host, port, login_handler, login_data, user_agent, cached_sock);

	const char **ci = cafiles;
	client->is_tls = 1;

	if(ci) {
		int c=0;
		while (*ci) {
			c++;
			ci++;
		}
		client->tls_cafiles = malloc (sizeof(char*) * (c+1));
		memcpy (client->tls_cafiles, cafiles, sizeof(char*) * (c + 1));
	}

	return (trest_ptr) client;
}


trest_ptr
trest_new_tls_from_userpass(const char* host, int port,
			    const char *user,
			    const char *pass,
			    const char **cafiles,
			    const char *user_agent,
			    const struct sockaddr *cached_sock)
{
	struct trest* client = (struct trest*)
		trest_new_from_userpass(host, port, user, pass, user_agent, cached_sock);

	const char **ci = cafiles;
	client->is_tls = 1;

	if(ci) {
		int c=0;
		while (*ci) {
			c++;
			ci++;
		}
		client->tls_cafiles = malloc (sizeof(char*) * (c+1));
		memcpy (client->tls_cafiles, cafiles, sizeof(char*) * (c + 1));
	}

	return (trest_ptr) client;
}

void
trest_free (trest_ptr ptr)
{
	struct trest* client = (struct trest*) ptr;
	char **cptr = client->credentials;

	if (cptr) {
		while(*cptr) {
			free (*cptr++);
		}
	}
	if (client->access_token)
		free(client->access_token);
	if (client->refresh_token)
		free(client->refresh_token);
	if (client->tls_cafiles)
		free(client->tls_cafiles);
	free(client->credentials);
	free(client->host);
	free (ptr);
	return;
}

void
trest_request_free (trest_request_ptr ptr)
{
	struct trest_request* req = (struct trest_request*) ptr;

	if (req->on_free)
		req->on_free(req);

	free(req);
}

void
trest_response_free (trest_response_ptr ptr)
{
	if (ptr->body)
		free(ptr->body);
	if(ptr->json_tokv)
		free(ptr->json_tokv);
	free(ptr);
}

// check auth status if you are just interested in this
trest_auth_status_enum
trest_auth_status (trest_ptr ptr)
{
	struct trest *self = (struct trest*) ptr;
	return self->status;
}


// update auth tokens if possible. usually tries refresh_token
// against the login endpoint and then other credentials
// if available. usually needs to be called once to get
// initial auth token, but this behaviour depends on the
// credential type and backend implementation.
trest_auth_status_enum
trest_update_auth (trest_ptr ptr)
{
	struct trest *self = (struct trest*) ptr;
	// if we believe we are authed, use refresh logic...
	if (trest_auth_status (ptr) == TREST_AUTH_STATUS_OK) {
		return do_refresh_login (self);
	} else {
		return do_credentials_login (self);
	}

	return TREST_AUTH_STATUS_UNKNOWN;
}

static void trest_free_make_request(struct trest_request *req)
{
	if (req->endpoint_path)
		free(req->endpoint_path);
	if (req->json_body)
		free(req->json_body);
	if (req->queries) {
		while (req->nr_queries) {
			req->nr_queries--;
			if (req->queries[req->nr_queries])
				free(req->queries[req->nr_queries]);
		}
		free(req->queries);
	}
	if (req->headers) {
		while (req->nr_headers) {
			req->nr_headers--;
			if (req->headers[req->nr_headers])
				free(req->headers[req->nr_headers]);
		}
		free(req->headers);
	}
}

static int __trest_add_request_hq(trest_request_ptr ptr, char **hdr_or_queries, 
					enum trest_req_alloc_type type)
{
	char ***dest = NULL;
	int *count = NULL;
	int added = 0;
	struct trest_request *r = (struct trest_request*)ptr;
	char **walker = hdr_or_queries;

	switch (type) {
		case TREST_ALLOC_HEADER:
			dest = &r->headers;
			count = &r->nr_headers;
			break;
		case TREST_ALLOC_QUERY:
			dest = &r->queries;
			count = &r->nr_queries;
			break;
		default:
			dest = NULL;
			count = NULL;
			break;
	}

	if (!dest || !count)
		goto out;

	if (!*dest) {
		*dest = calloc(2, sizeof(char*));
	}

	if (!*dest)
		goto out;
	while (walker && *walker) {
		if (!*count) {
			(*dest)[*count] = strdup(*walker);
			(*count)++;
			added++;
		} else {
			if ( !((*count + 1) & (*count))) {
				char **new_dest = NULL;
				char new_size = (*count + 1) * 2;
				
				new_dest = realloc(*dest, sizeof(char*) * new_size);
				if (new_dest) {
					*dest = new_dest;
					memset(*dest + *count, 0,
						(new_size - *count) * sizeof(char*));
				} else
					break; /*Do as many headers as we can*/
			}
			(*dest)[*count] = strdup(*walker);
			(*count)++;
			added++;
		}
		walker++;
	}
out:
	return added;
}

int trest_add_queries(trest_request_ptr ptr, char **queries)
{
	return __trest_add_request_hq(ptr, queries, TREST_ALLOC_QUERY);
}

/*
 * Allocate as headers as power of 2.
 * */
int trest_add_headers(trest_request_ptr ptr, char **headers) 
{
	return __trest_add_request_hq(ptr, headers, TREST_ALLOC_HEADER);
}
// make a json request; uses Encoding application/json
// and Accept-Endcoding application/json accordingly
trest_request_ptr
trest_make_request (trest_method_enum method,
		    char *endpoint_path,
		    char **queries,
		    char **headers,
		    char *json_body)
{
	// XXX: implement parameter precondition checks
	struct trest_request* r =
		malloc (sizeof(struct trest_request));

	if (!r)
		goto no_request;

	r->method = method;
	r->endpoint_path = strdup(endpoint_path);
	r->json_body = json_body ? strdup(json_body) : 0;
	r->queries = 0;
	r->headers = 0;
	r->nr_queries = 0;
	r->nr_headers = 0;
	r->on_free = trest_free_make_request;
	trest_add_queries(r, queries);
	trest_add_headers(r, headers);
no_request:
	return r;
}

// execute the request.
// XXX: later or think about:
//   -- this will autoperform redirects
//   -- if they are going to the same service. The service
//   -- endpoint prefix is determined through a setting that
//   -- can be tweaked against the _request objects. By
//   -- default the client uses.
trest_response_ptr
trest_do_request (trest_ptr client,
		  trest_request_ptr request,
		  trest_cb callback,
		  void* user_data)
{
	return NULL;
}


static trest_response_ptr
__trest_do_json_request (trest_ptr client,
		       trest_request_ptr request)
{

	thttp_response_t *response;
	thttp_request_t *req;
	trest_response_t *res = calloc (1, sizeof(trest_response_t));
	struct trest_request *req_in = (struct trest_request*) request;
	struct trest *c = (struct trest*) client;
	static char do_login_userpass = 0;

	if (!res)
		goto exit;

	if (!c->is_tls) {
		req = thttp_request_new_0();
	} else {
		req = (thttp_request_t*) thttp_request_tls_new_0();
	}

	if (!req)
		goto exit;

	if (c->is_tls)
		((thttp_request_tls_t*)req)->crtfiles = c->tls_cafiles;

	req->method = req_in->method;
	req->proto = THTTP_PROTO_HTTP;
	req->proto_version = THTTP_PROTO_VERSION_10;
	req->path = req_in->endpoint_path;
	req->user_agent = c->user_agent;
	req->host = c->host;
	req->port = c->port;
	req->body = req_in->json_body;
	req->headers = req_in->headers;
	req->conn = c->conn;
	if (req_in->json_body)
		req->body_content_type = "application/json";

	// XXX: this below assumes that header array has two 0 elements
	// at the end already allocated; too horrible approach; refactor to
	// use argz glibc extension instead for headers and queries
	if (c->access_token) {
		const char *autht = "Authorization: Bearer %s";
		char *headers_i = NULL;
		
		headers_i = malloc(strlen(autht) + strlen (c->access_token) + 1);
		if (headers_i) {
			char *headers[] = {headers_i, NULL};

			sprintf (headers_i, autht, c->access_token);
			if (trest_add_headers(req_in, headers) == 1) {
				req->headers = req_in->headers;
			}
			if (DEBUG)
				printf("Added access_token header: %s\n", headers_i);
		}
	}

	response = thttp_request_do(req);
	if (!response)
		goto free_req;

	if (response->body) {
		res->body = strdup(response->body);
		if (!res->body) {
			res->body = response->body;
			response->body = NULL;
		}
		res->json_tokc = jsmnutil_parse_json (res->body, &res->json_tokv, &res->json_toks);
		if (!res->json_tokc)
		{
			// XXX: update auth status of response?
			printf ("failed to parse_json\n");
			trest_response_free(res);
			thttp_response_free(response);
			res = 0;
			goto free_req;
		}
	}
	// XXX: strvdup this one...
	res->headers = response->headers;
	res->code = response->code;

	switch (response->code) {
	case THTTP_STATUS_UNAUTHORIZED:
		res->status = TREST_AUTH_STATUS_NOTAUTH;

		if (!do_login_userpass) {
			do_login_userpass = 1;
			do_credentials_login(c);
		}
	break;
	case THTTP_STATUS_OK:
		res->status = TREST_AUTH_STATUS_OK;
	break;
	default:
		res->status = TREST_AUTH_STATUS_ERROR;
		// XXX: this needs to be redone in a way that guides
		// clients on how to solve...
	}

	thttp_response_free(response);
free_req:
	thttp_request_free(req);

	if (do_login_userpass)
		do_login_userpass = 0;
exit:
	return (trest_response_ptr) res;
}

trest_response_ptr
trest_do_json_request (trest_ptr client,
		       trest_request_ptr request)
{
	struct trest *c = (struct trest*) client;
	trest_response_ptr res = NULL;
	int tried = 0;

restart_request:
	res = __trest_do_json_request(client, request);
	if (res) {
		/*
		 * Were we able to refresh credentials? If yes attempt
		 * to restart this request again.
		 */
		if (!tried && res->status == TREST_AUTH_STATUS_NOTAUTH &&
				c->status == TREST_AUTH_STATUS_OK) {
			trest_response_free(res);
			res = NULL;
			tried = 1;
			goto restart_request;
		}
	}
	return res;
}

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
