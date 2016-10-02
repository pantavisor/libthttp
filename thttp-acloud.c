
#include <stdlib.h>
#include <string.h>

#include "thttp-acloud.h"

enum tcloudc_rtype {
	tcloudc_rtype_JSON =1,
	tcloudc_rtype_BLOB,
};

struct tcloudc_client {
	char *host;
	int port;

	char **credentials;
	char *access_token;
	char *refresh_token;
};

struct tcloudc_request {
	enum tcloudc_rtype type;
	tcloudc_method_enum method;

	char *endpoint_path;
	char **queries;
	char *json_body;
};

struct tcloudc_response {
};


tcloudc_client_ptr
tcloudc_client_new_from_userpass(const char* host, int port,
				const char *user,
				const char *pass)
{
	struct tcloudc_client* client =
		calloc (sizeof(struct tcloudc_client*), 1);

	client->host = strdup(host);
	client->port = port;

	client->credentials = malloc(sizeof(char*) * 3);
	*client->credentials++ = strdup(user);
	*client->credentials++ = strdup(pass);
	*client->credentials = (char*) 0;

	return (tcloudc_client_ptr*) client;
}

void
tcloudc_client_free (tcloudc_client_ptr ptr)
{
	struct tcloudc_client* client = (struct tcloudc_client*) ptr;
	char **cptr = client->credentials;

	while(cptr && *cptr) {
		free (*cptr++);
	}

	if (cptr) {
		free(cptr);
	}

	return;
}

void
tcloudc_request_free (tcloudc_request_ptr ptr)
{
	struct tcloudc_request* req = (struct tcloudc_request*) ptr;
	char **queries_i = req->queries;

	while(queries_i && *queries_i)
		free(queries_i++);

	free(req->queries);
	free(req->endpoint_path);
	free(req->json_body);
}

void
tcloudc_response_free (tcloudc_response_ptr ptr)
{
}

// check auth status if you are just interested in this
tcloudc_auth_status_enum
tcloudc_auth_status (tcloudc_client_ptr ptr)
{
	return TCLOUDC_AUTH_STATUS_UNKNOWN;
}

// make a json request; uses Encoding application/json
// and Accept-Endcoding application/json accordingly
tcloudc_request_ptr
tcloudc_make_request (tcloudc_method_enum method,
		char *endpoint_path,
		char **queries,
		char *json_body)
{
	// XXX: implement parameter precondition checks
	struct tcloudc_request* r =
		malloc (sizeof(struct tcloudc_request*));

	size_t queries_size = 1;
	int queries_len = 0;
	char **queries_i = queries;

	r->queries = calloc(sizeof(char*), queries_size);
	r->queries[queries_len] = 0;

	r->method = method;
	r->endpoint_path = strdup(endpoint_path);
	r->json_body= strdup(json_body);

	// XXX: make a ptrvdup
	while (queries && *queries) {
		queries_len++;
		if (queries_len >= queries_size) {
			queries_size += 128 * sizeof(char*);
			r->queries = realloc(r->queries, queries_size);
			r->queries[queries_len++] = *queries++;
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
tcloudc_response_ptr
tcloud_client_do_request (tcloudc_client_ptr *client,
			tcloudc_request_ptr request,
			tcloudc_client_cb callback,
			void* user_data)
{
	return NULL;
}

tcloudc_response_ptr
tcloud_client_do__json_request (tcloudc_client_ptr *client,
				tcloudc_request_ptr request)
{
	return NULL;
}

// callback for blob messages. this gets called when
// new data is available with data pointing to the
// received data buffer and data_len having info about
// the data buffer size retrieved.
// Special conditions are treated like the following:
//  - EOF:  data == 0 && data_len == 0
//  - ERROR" data == 0 && data_len == ERROR_CODE
typedef void (*tcloudc_client_cb) (void *user_data,
				unsigned char* data,
				size_t data_len);
