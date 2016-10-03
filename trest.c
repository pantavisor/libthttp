
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jsmn/jsmn.h"
#include "trest.h"
#include "thttp.h"

enum trest_rtype {
	trest_rtype_JSON =1,
	trest_rtype_BLOB,
};

enum trest_auth_type {
	trest_auth_type_BASIC=0,
	trest_auth_type_DAUTH,
	trest_auth_type_UNKNOWN=10000
};


struct trest {
	enum trest_auth_type type;
	trest_auth_status_enum status;

	char *host;
	int port;

	char **credentials;
	char *access_token;
	char *refresh_token;
};

struct trest_request {
	enum trest_rtype type;
	t_thttp_method method;

	char *endpoint_path;
	char **queries;
	char *json_body;
};

trest_ptr
trest_new_from_userpass(const char* host, int port,
				const char *user,
				const char *pass)
{
	struct trest* client =
		calloc (sizeof(struct trest), 1);

	client->host = strdup(host);
	client->port = port;
	client->type = trest_auth_type_BASIC;
	client->status = TREST_AUTH_STATUS_NOTAUTH;

	client->credentials = malloc(sizeof(char*) * 3);
	client->credentials[0] = strdup(user);
	client->credentials[1] = strdup(pass);
	client->credentials[2] = (char*) 0;

	return (trest_ptr) client;
}

void
trest_free (trest_ptr ptr)
{
	struct trest* client = (struct trest*) ptr;
	char **cptr = client->credentials;

	while(*cptr) {
		free (*cptr++);
	}

	free(client->credentials);
	free(client->host);
	free (ptr);
	return;
}

void
trest_request_free (trest_request_ptr ptr)
{
	struct trest_request* req = (struct trest_request*) ptr;

	if (req->queries) {
		char **queries_i = req->queries;
		while(*queries_i) {
			free(*queries_i);
			queries_i++;
		}
	}

	free(req->queries);
	free(req->endpoint_path);
	free(req->json_body);
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
	return TREST_AUTH_STATUS_UNKNOWN;
}

// make a json request; uses Encoding application/json
// and Accept-Endcoding application/json accordingly
trest_request_ptr
trest_make_request (trest_method_enum method,
		char *endpoint_path,
		char **queries,
		char *json_body)
{
	// XXX: implement parameter precondition checks
	struct trest_request* r =
		malloc (sizeof(struct trest_request));

	char **queries_i = queries;

	r->method = method;
	r->endpoint_path = strdup(endpoint_path);
	r->json_body= strdup(json_body);
	r->queries = 0;

	if (queries_i) {
		size_t queries_size = 1;
		int queries_len = 0;
		r->queries = calloc(sizeof(char*), queries_size);
		r->queries[queries_len] = 0;

		// XXX: make a ptrvdup
		while (*queries_i) {
			r->queries[queries_len] = strdup(*queries_i++);
			queries_len++;
			if (queries_len >= queries_size) {
				queries_size += 128 * sizeof(char*);
				r->queries = realloc(r->queries, queries_size);
			}
		}
	}
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

static int
parse_json (const char *buf, jsmntok_t **jsonv_out, int *jsonc_out)
{
	jsmn_parser parser;
	int r;

	jsmn_init (&parser);

	*jsonc_out=10;
	*jsonv_out = malloc (*jsonc_out * sizeof(jsmntok_t));

	if (*jsonv_out == NULL) {
		fprintf(stderr, "malloc(): errno=%d\n", errno);
		return 0;
	}
again:
	r = jsmn_parse(&parser, buf, strlen (buf), *jsonv_out,
		*jsonc_out);

	if (r < 0) {
		if (r == JSMN_ERROR_NOMEM) {
			*jsonc_out = *jsonc_out * 2;
			*jsonv_out = realloc(*jsonv_out, sizeof(jsmntok_t)
					* *jsonc_out);
			if (jsonv_out == NULL) {
				return 0;
			}
			goto again;
		}
	}
	return *jsonc_out;
}

trest_response_ptr
trest_do_json_request (trest_ptr client,
			trest_request_ptr request)
{

	t_thttp_request *req = thttp_request_new_0();
	trest_response_t *res = calloc (sizeof(trest_response_t),1);
	struct trest_request *req_in = (struct trest_request*) request;
	struct trest *c = (struct trest*) client;
	jsmntok_t *tokv;
	int tokc;

	req->method = req_in->method;
	req->proto = THTTP_PROTO_HTTP;
	req->proto_version = THTTP_PROTO_VERSION_10;
	req->use_tls=0;
	req->path = req_in->endpoint_path;
	req->host = c->host;
	req->port = c->port;
	req->body = 0;
	req->headers = 0;

	t_thttp_response *response = thttp_request_do(req);
	res->body = strdup(response->body);
	res->headers = response->headers;

	if (!parse_json (response->body, &res->json_tokv, &res->json_tokc))
	{
		// XXX: update auth status of response?
		printf ("failed to parse_json\n");
		trest_response_free(res);
		res = 0;
	}

	thttp_request_free(req);
	thttp_response_free(response);

	return (trest_response_ptr) res;
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
