
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

	int is_tls;
	char **tls_cafiles;
};

struct trest_request {
	enum trest_rtype type;
	t_thttp_method method;

	char *endpoint_path;
	char **queries;
	char **headers;
	char *json_body;
};

static int
parse_json (const char *buf, jsmntok_t **jsonv_out, int *jsons_out)
{
	jsmn_parser parser;
	int r;

	jsmn_init (&parser);

	*jsons_out=10;
	*jsonv_out = malloc (*jsons_out * sizeof(jsmntok_t));

	if (*jsonv_out == NULL) {
		fprintf(stderr, "malloc(): errno=%d\n", errno);
		return 0;
	}
again:
	r = jsmn_parse(&parser, buf, strlen (buf), *jsonv_out,
		       *jsons_out);

	if (r < 0) {
		if (r == JSMN_ERROR_NOMEM) {
			*jsons_out = *jsons_out * 2;
			*jsonv_out = realloc(*jsonv_out, sizeof(jsmntok_t)
					     * *jsons_out);
			if (jsonv_out == NULL) {
				return 0;
			}
			goto again;
		}
	}
	return r;
}

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
	const char *htmpl = "Authorization: Bearer %s";
	trest_response_ptr r;
	char **h = malloc (sizeof(char*) * 2);

	h[0] = malloc (sizeof(char) *
		       (strlen(htmpl)
			+ strlen (self->refresh_token)));
	sprintf(h[0], htmpl, self->refresh_token);

	h[1] = 0;

	if (DEBUG)
		printf ("refresh login with: %s\n", h[0]);

	trest_request_ptr p = trest_make_request (TREST_METHOD_GET,
						  "/api/auth/login",
						  NULL,
						  h,
						  NULL);
	free (h[0]);
	free (h);

	r = trest_do_json_request (self, p);

	if (r->code == THTTP_STATUS_UNAUTHORIZED) {
		self->status = TREST_AUTH_STATUS_NOTAUTH;
		goto exit;
	} else if (r->code != THTTP_STATUS_OK) {
		self->status = TREST_AUTH_STATUS_ERROR;
		goto exit;
	}
	update_tokens_from_json_response (self, r);

	self->status = TREST_AUTH_STATUS_OK;
exit:
	trest_request_free(p);
	trest_response_free(r);
	return self->status;
}

static trest_auth_status_enum
do_credentials_login (struct trest *self)
{
	trest_response_ptr r;
	trest_request_ptr p;

	const char* userpass =
		"{ \"username\": \"%s\""
		", \"password\": \"%s\" }";

	char *b = malloc (sizeof(char) *
			  (strlen(userpass)
			   + strlen(self->credentials[0])
			   + strlen(self->credentials[1])));

	int rv = sprintf(b, userpass, self->credentials[0], self->credentials[1]);

	if (DEBUG)
		printf ("do_credentials_login with body : %s\n", b);

	p = trest_make_request (TREST_METHOD_POST,
				"/api/auth/login",
				NULL,
				NULL,
				b);
	free (b);

	r = trest_do_json_request (self, p);

	if (DEBUG)
		printf ("do_credentials_login code: %d\n", r->code);
	if (r->code == THTTP_STATUS_UNAUTHORIZED) {
		self->status = TREST_AUTH_STATUS_NOTAUTH;
		goto exit;
	} else if (r->code != THTTP_STATUS_OK) {
		self->status = TREST_AUTH_STATUS_ERROR;
		goto exit;
	}
	update_tokens_from_json_response (self, r);

	self->status = TREST_AUTH_STATUS_OK;
exit:
	trest_request_free(p);
	trest_response_free(r);
	return self->status;
}


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

trest_ptr
trest_new_tls_from_userpass(const char* host, int port,
			    const char *user,
			    const char *pass,
			    const char **cafiles)
{
	struct trest* client = (struct trest*)
		trest_new_from_userpass(host, port, user, pass);

	const char **ci = cafiles;
	client->is_tls = 1;

	if(ci) {
		int c=0;
		while (*ci) {
			c++;
			ci++;
		}

		client->tls_cafiles = malloc (sizeof(char*) * (c+1));
		memcpy (client->tls_cafiles, cafiles, c+1);
	}

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

	if (req->json_body)
		free(req->json_body);

	if (req->queries) {
		char **queries_i = req->queries;
		while(*queries_i) {
			free(*queries_i);
			queries_i++;
		}
		free(req->queries);
	}

	if (req->headers) {
		char **headers_i = req->headers;
		while(*headers_i) {
			free(*headers_i);
			headers_i++;
		}
		free(req->headers);
	}

	if(req->endpoint_path)
		free(req->endpoint_path);

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

	char **queries_i = queries;
	char **headers_i = headers;
	int headers_size;
	int headers_len;

	r->method = method;
	r->endpoint_path = strdup(endpoint_path);
	r->json_body = json_body ? strdup(json_body) : 0;
	r->queries = 0;
	r->headers = 0;

	if (!queries_i)
		goto headers;

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

headers:
	headers_size = 2;
	headers_len = 0;
	r->headers = calloc(sizeof(char*), headers_size);

	if (!headers_i)
		goto no_headers;

	// XXX: make a ptrvdup
	while (*headers_i) {
		r->headers[headers_len] = strdup(*headers_i);
		headers_len++;
		headers_i++;
		if (headers_len+1 >= headers_size) {
			headers_size += 128;
			r->headers = realloc(r->headers, sizeof(char*) * headers_size);
		}
	}

no_headers:
	r->headers[headers_len] = 0;
	r->headers[headers_len+1] = 0;

exit:
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


trest_response_ptr
trest_do_json_request (trest_ptr client,
		       trest_request_ptr request)
{

	t_thttp_response *response;
	t_thttp_request *req;
	trest_response_t *res = calloc (sizeof(trest_response_t),1);
	struct trest_request *req_in = (struct trest_request*) request;
	struct trest *c = (struct trest*) client;
	jsmntok_t *tokv;
	int tokc;

	if (!c->is_tls) {
		req = thttp_request_new_0();
	} else {
		req = (t_thttp_request*) thttp_request_tls_new_0();
		((t_thttp_request_tls*)req)->crtfiles = c->tls_cafiles;
	}

	req->method = req_in->method;
	req->proto = THTTP_PROTO_HTTP;
	req->proto_version = THTTP_PROTO_VERSION_10;
	req->path = req_in->endpoint_path;
	req->host = c->host;
	req->port = c->port;
	req->body = req_in->json_body;
	req->headers = req_in->headers;
	if (req_in->json_body)
		req->body_content_type = "application/json";

	// XXX: this below assumes that header array has two 0 elements
	// at the end already allocated; too horrible approach; refactor to
	// use argz glibc extension instead for headers and queries
	if (c->access_token) {
		const char *autht = "Authorization: Bearer %s";
		char **headers_i = req->headers;
		while (*headers_i)
			headers_i++;
		*headers_i = malloc ((strlen(autht) + strlen (c->access_token)) * sizeof(char));
		sprintf (*headers_i, autht, c->access_token);
		if (DEBUG)
			printf("Added access_token header: %s\n", *headers_i);
		if (*++headers_i != 0)
			printf("ERROR: ARRAY MUST BE NULL TERMINATED\n");
	}


	response = thttp_request_do(req);

	if (response->body) {
		int jc;
		res->body = strdup(response->body);
		res->json_tokc = parse_json (response->body, &res->json_tokv, &res->json_toks);
		if (!res->json_tokc)
		{
			// XXX: update auth status of response?
			printf ("failed to parse_json\n");
			trest_response_free(res);
			res = 0;
		}
	}
	// XXX: strvdup this one...
	res->headers = response->headers;
	res->code = response->code;

	switch (response->code) {
	case THTTP_STATUS_UNAUTHORIZED:
		res->status = TREST_AUTH_STATUS_NOTAUTH;
	case THTTP_STATUS_OK:
		res->status = TREST_AUTH_STATUS_OK;
	default:
		res->status = TREST_AUTH_STATUS_ERROR;
		// XXX: this needs to be redone in a way that guides
		// clients on how to solve...
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
