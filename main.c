#include <stdio.h>

#include "thttp.h"

int main (char **argv, int argc) {

	t_thttp_request* req = thttp_request_new_0 ();
	t_thttp_response* res = 0;

	req->method = THTTP_METHOD_POST;
	req->proto = THTTP_PROTO_HTTP;
	req->proto_version = THTTP_PROTO_VERSION_10;
	req->use_tls = 0;
	req->host = "localhost";
	req->port = 12365;
	req->path = "/api/auth/login";
	req->headers = 0;
	req->body =
		"{"
		"	\"username\": \"user1\","
		"	\"password\": \"user1\""
		"}";
	req->body_content_type = "application/json";

	res = thttp_request_do (req);

	printf("\nResult Retrieved:\n%s\n", res->body);

	thttp_request_free(req);
	thttp_response_free(res);
	return 0;
}
