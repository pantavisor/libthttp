/*
 * Copyright (c) 2017-2021 Pantacor Ltd.
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
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include "jsmn/jsmnutil.h"
#include "thttp.h"
#include "utils-example1.h"

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

static char*
get_json_key_value(char *buf, char *key, jsmntok_t* tok, int tokc)
{
	int i;
	int t=-1;

	for(i=0; i<tokc; i++) {
		int n = tok[i].end - tok[i].start;
		if (tok[i].type == JSMN_STRING
		    && !strncmp(buf + tok[i].start, key, n)) {
			t=1;
		} else if (t==1) {
			char *idval = malloc(n+1);
			idval[n] = 0;
			strncpy(idval, buf + tok[i].start, n);
			return idval;
		} else if (t==1) {
			printf ("ERROR: json does not have 'key' string\n");
			return NULL;
		}
	}
	return NULL;
}

char *https_proxy_env;
char *thttp_user;
char *thttp_pass;
char *thttp_apihost;
char *thttp_apiport;
char *thttp_apiproto;
char *thttp_noproxyconnect;
char *thttp_objectid;

static int setup_request(thttp_request_t *req) {

	int r;

	req->host_proxy = NULL;
	req->port_proxy = 3128;

	if (https_proxy_env) {
		char ip[100];
		char proto[100];
		int port = -1;
		char page[100];
		if ( sscanf(https_proxy_env, "%99[a-z]://%99[^:]/%99[^\n]", proto, ip, page) < 3) {
			r = sscanf(https_proxy_env, "%99[a-z]://%99[^:]:%99d/%99[^\n]", proto, ip, &port, page);
		}

		if ( r <= 0 ) {
			printf("ERROR: problem parsing https_proxy env (%s); illegal URL format\n", https_proxy_env);
			return 128;
		}

		if (!strcmp ("http", proto)) {
			if (port == -1)
				port = 80;
			req->is_tls = 0;
		} else if (!strcmp ("https", proto)) {
			if (port == -1)
				port = 443;
		} else {
			printf("ERROR: unsupported protocol (%s) in https_proxy URL (%s)\n", proto, https_proxy_env);
			return 129;
		}

		req->host_proxy = strdup(ip);
		req->port_proxy = port;
	}

	printf("PH: %s, PP: %d\n", req->host_proxy ? req->host_proxy : "", req->port_proxy);

	if (!thttp_noproxyconnect) {
		req->proxyconnect = 1;
	}

	req->method = THTTP_METHOD_GET;
	req->proto = THTTP_PROTO_HTTP;
	req->proto_version = THTTP_PROTO_VERSION_10;
	req->user_agent = "Libthttp Test/1.0";
	req->host = make_message("%s", thttp_apihost ? thttp_apihost : "api.pantahub.com");
	req->port = thttp_apiport ? atoi(thttp_apiport) : 443;
	req->path = "/auth/login";
	req->baseurl = make_message("%s://%s:%d",
				    thttp_apiproto ? thttp_apiproto : "https",
				    req->host, req->port);
	req->headers = 0;

	return 0;
}

int main (int argc, char **argv) {

	thttp_request_t* req = (thttp_request_t*) thttp_request_tls_new_0 ();
	thttp_response_t* res = 0;
	int r;
	char *token, *geturl;
	int tokcount;
	jsmntok_t *tok;
	jsmn_parser parser;

	https_proxy_env = getenv("https_proxy");
	thttp_user = getenv("THTTP_USER");
	thttp_pass = getenv("THTTP_PASS");
	thttp_apihost = getenv("THTTP_APIHOST");
	thttp_apiport = getenv("THTTP_APIPORT");
	thttp_apiproto = getenv("THTTP_APIPROTO");
	thttp_noproxyconnect = getenv("THTTP_NOPROXYCONNECT");
	thttp_objectid = getenv("THTTP_OBJECTID");


	/* Authenticate */
	setup_request (req);
	req->method = THTTP_METHOD_POST;
	req->body = make_message(
		"{"
		"	\"username\": \"%s\","
		"	\"password\": \"%s\""
		"}",
		thttp_user ? thttp_user : "user1",
		thttp_pass ? thttp_pass : "user1");
	req->body_content_type = "application/json";
	printf("calling %s://%s:%d%s\n", req->is_tls ? "https" : "http", req->host_proxy ? req->host_proxy : "", req->port_proxy, req->path);
	res = thttp_request_do (req);
	printf("\nResult Retrieved:\n%s\n", res->body);


	jsmn_init (&parser);
	r = jsmnutil_parse_json (res->body, &tok, &tokcount);
	token = get_json_key_value(res->body, "token", tok, r);
	printf("TOKEN: %s\n", token);
	free(tok);
	thttp_request_free(req);
	thttp_response_free(res);

	/* Get Object */
	req = (thttp_request_t*) thttp_request_tls_new_0 ();
	setup_request (req);
	req->path = make_message ("/objects/%s", thttp_objectid ? thttp_objectid : "0a6616d49e5853276af57d2bcdea96e51baa1a4c1227c4447c268ec66f93a110") ;
	req->baseurl = make_message("%s://%s:%d",
				    thttp_apiproto ? thttp_apiproto : "https",
				    req->host, req->port);
	req->headers = calloc(sizeof(char*), 2);
	req->headers[0] = make_message("Authorization: Bearer %s", token);
	req->body = "";
	req->body_content_type = "";
	res = thttp_request_do (req);
	printf("\n%s: Result Retrieved:\n%s\n", req->path, res->body);
	jsmn_init (&parser);
	r = jsmnutil_parse_json (res->body, &tok, &tokcount);
	geturl = get_json_key_value(res->body, "signed-geturl", tok, r);
	printf("GETURL: %d :: %s\n", r, geturl);
	free(tok);
	thttp_request_free(req);
	thttp_response_free(res);

	/* Download Object */
	req = (thttp_request_t*) thttp_request_tls_new_0 ();
	setup_request (req);
	req->path = geturl;
	req->baseurl = NULL;
	req->headers = 0;
	req->body = "";
	req->body_content_type = "";
	int fd;
	char name[] = "/tmp/fileXXXXXX";
	fd = mkstemp(name);
	res = thttp_request_do_file (req, fd);
	close (fd);
	printf("\nResult Retrieved in:\n%s\n", name);

	return 0;
}
