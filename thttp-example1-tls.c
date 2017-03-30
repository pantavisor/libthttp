
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "jsmn/jsmn.h"
#include "thttp.h"

static int
dump_json (const char *js, jsmntok_t *t, size_t count, int indent) {
	int i, j, k;
	if (count == 0) {
		return 0;
	}
	if (t->type == JSMN_PRIMITIVE) {
		printf("%.*s", t->end - t->start, js+t->start);
		return 1;
	} else if (t->type == JSMN_STRING) {
		printf("'%.*s'", t->end - t->start, js+t->start);
		return 1;
	} else if (t->type == JSMN_OBJECT) {
		printf("\n");
		j = 0;
		for (i = 0; i < t->size; i++) {
			for (k = 0; k < indent; k++) printf("  ");
			j += dump_json (js, t+1+j, count-j, indent+1);
			printf(": ");
			j += dump_json(js, t+1+j, count-j, indent+1);
			printf("\n");
		}
		return j+1;
	} else if (t->type == JSMN_ARRAY) {
		j = 0;
		printf("\n");
		for (i = 0; i < t->size; i++) {
			for (k = 0; k < indent-1; k++) printf("  ");
			printf("   - ");
			j += dump_json(js, t+1+j, count-j, indent+1);
			printf("\n");
		}
		return j+1;
	}
	return 0;
}

int main (char **argv, int argc) {

	thttp_request_t* req = (thttp_request_t*) thttp_request_tls_new_0 ();
	thttp_response_t* res = 0;
	int r;

	req->method = THTTP_METHOD_POST;
	req->proto = THTTP_PROTO_HTTP;
	req->proto_version = THTTP_PROTO_VERSION_10;
	req->host = "localhost";
	req->port = 12366;
	req->path = "/auth/login";
	req->headers = 0;
	req->body =
		"{"
		"	\"username\": \"user1\","
		"	\"password\": \"user1\""
		"}";
	req->body_content_type = "application/json";

	res = thttp_request_do (req);

	printf("\nResult Retrieved:\n%s\n", res->body);


	int tokcount=10;
	jsmntok_t *tok;
	jsmn_parser parser;
	jsmn_init (&parser);

	tok = malloc (tokcount * sizeof(*tok));

	if (tok == NULL) {
		fprintf(stderr, "malloc(): errno=%d\n", errno);
		return 3;
	}


again:
	r = jsmn_parse(&parser, res->body, strlen (res->body), tok, tokcount);
	if (r < 0) {
		if (r == JSMN_ERROR_NOMEM) {
			tokcount = tokcount * 2;
			tok = realloc(tok, sizeof(*tok) * tokcount);
			if (tok == NULL) {
				return 3;
			}
			goto again;
		}
	} else {
		dump_json (res->body, tok, parser.toknext, 0);
	}
	free(tok);

	thttp_request_free(req);
	thttp_response_free(res);

	req = thttp_request_new_0 ();

	req->method = THTTP_METHOD_POST;
	req->proto = THTTP_PROTO_HTTP;
	req->proto_version = THTTP_PROTO_VERSION_10;
	req->host = "localhost";
	req->port = 12365;
	req->path = "/auth/login";
	req->headers = 0;
	req->body =
		"{"
		"	\"username\": \"user1\","
		"	\"password\": \"user1\""
		"}";
	req->body_content_type = "application/json";

	int fd;
	char name[] = "/tmp/fileXXXXXX";
	fd = mkstemp(name);

	res = thttp_request_do_file (req, fd);

	close (fd);
	printf("\nResult Retrieved in:\n%s\n", name);

	thttp_request_free(req);
	thttp_response_free(res);

	return 0;
}
