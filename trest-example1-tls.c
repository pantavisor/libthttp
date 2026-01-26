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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trest.h"
#include "jsmn/jsmnutil.h"
#include "utils-example1.h"

#define DEFAULT_HOST "api2.pantahub.com"
#define DEFAULT_PORT "443"
#define DEFAULT_USER "user1"
#define DEFAULT_USERPASS "user1"
#define DEFAULT_BADPASS "badpassword"
#define DEFAULT_DEVICEPASS "device1"
#define DEFAULT_USERAGENT "trest/1.0 (development build)"

#define DEVICE_TRAIL_ENDPOINT_FMT "/trails/%s/steps"

char *https_proxy_env;
char *trest_user;
char *trest_pass;
char *trest_apihost;
char *trest_apiport;
char *trest_apiproto;
char *trest_noproxyconnect;
char *trest_cafiles;

typedef void (*token_iter_f)(void *data, char *buf, jsmntok_t *tok, int c);

#define BUF 256

static const char **splitstr(char *buf, const char *delim)
{
	char *tok;
	int i = 0, s = 0;
	const char **res = 0;

	tok = strtok(buf, delim);
	while (tok) {
		if (i + 1 >= s) {
			s += BUF;
			res = realloc(res, sizeof(char *) * s);
		}
		res[i++] = tok;
		res[i] = 0;
		tok = strtok(NULL, delim);
	}
	return res;
}

static int traverse_token(char *buf, jsmntok_t *tok, int t)
{
	int i;
	int c;
	c = t;
	for (i = 0; i < tok[t].size; i++) {
		c = traverse_token(buf, tok, c + 1);
	}
	return c;
}

// is good for getting elements of any array type token. Just point tok+t to the
// token of type array and it will iterate the direct children of that token
// through travesal the depth first token array.
static int iterate_json_array(char *buf, jsmntok_t *tok, int t,
			      token_iter_f func, void *data)
{
	int i;
	int c;
	if (tok[t].type != JSMN_ARRAY) {
		printf("iterare_json_array: token not array");
		return -1;
	}

	c = t;
	for (i = 0; i < tok->size; i++) {
		func(data, buf, tok, c + 1);
		c = traverse_token(buf, tok, c + 1);
	}
	return 0;
}

static char *get_json_key_value(char *buf, char *key, jsmntok_t *tok, int tokc)
{
	int i;
	int t = -1;

	for (i = 0; i < tokc; i++) {
		int n = tok[i].end - tok[i].start;
		if (tok[i].type == JSMN_STRING &&
		    !strncmp(buf + tok[i].start, key, n)) {
			t = 1;
		} else if (t == 1) {
			char *idval = malloc(n + 1);
			idval[n] = 0;
			strncpy(idval, buf + tok[i].start, n);
			return idval;
		} else if (t == 1) {
			printf("ERROR: json does not have 'key' string\n");
			return NULL;
		}
	}
	return NULL;
}

static void print_step(void *data, char *buf, jsmntok_t *tok, int c)
{
	int n = (tok + c)->end - (tok + c)->start;
	char *s = malloc(sizeof(char) * n + 2);
	buf[n + 1] = 0;
	strncpy(s, buf + (tok + c)->start, n + 2);
	printf("TOKEN: start=%d, end=%d, buf=%s\n", (tok + c)->start,
	       (tok + c)->end, s);
	free(s);
}

static int setup_client(trest_ptr client)
{
	int r;

	if (https_proxy_env) {
		char ip[100];
		char proto[100];
		int port = -1;
		char page[100];
		int is_tls = 0;

		if (sscanf(https_proxy_env, "%99[a-z]://%99[^:]/%99[^\n]",
			   proto, ip, page) < 3) {
			r = sscanf(https_proxy_env,
				   "%99[a-z]://%99[^:]:%99d/%99[^\n]", proto,
				   ip, &port, page);
		}

		if (r <= 0) {
			printf("ERROR: problem parsing https_proxy env (%s); illegal URL format\n",
			       https_proxy_env);
			return 128;
		}

		if (!strcmp("http", proto)) {
			if (port == -1)
				port = 80;
			is_tls = 0;
		} else if (!strcmp("https", proto)) {
			if (port == -1)
				port = 443;
			is_tls = 1;
		} else {
			printf("ERROR: unsupported protocol (%s) in https_proxy URL (%s)\n",
			       proto, https_proxy_env);
			return 129;
		}

		trest_set_proxy_connect(client, strdup(ip), port, is_tls,
					!trest_noproxyconnect);
	}

	return 0;
}

int main(int argc, char **argv)
{
	int rv = 0, i;
	char *device_prn = 0, *device_id = 0, *device_nick = 0,
	     *device_secret = 0;
	char *trail_steps_ep = 0;
	trest_ptr badclient = 0, deviceclient = 0, userclient = 0;
	trest_response_ptr res = 0, res1 = 0, res2 = 0, res3 = 0, res4 = 0,
			   res4a = 0, res5 = 0, res6 = 0;
	trest_request_ptr req = 0, req1 = 0, req2 = 0, req3 = 0, req4 = 0,
			  req4a = 0, req5 = 0, req6 = 0;
	const char *server_host;
	const char **cafiles;
	trest_auth_status_enum status, auth_status;

	https_proxy_env = getenv("https_proxy");
	trest_user = getenv("TREST_USER");
	trest_pass = getenv("TREST_PASS");
	trest_apihost = getenv("TREST_APIHOST");
	trest_apiport = getenv("TREST_APIPORT");
	trest_apiproto = getenv("TREST_APIPROTO");
	trest_cafiles = getenv("TREST_CAFILES");
	trest_noproxyconnect = getenv("TREST_NOPROXYCONNECT");

	server_host = trest_apihost ? trest_apihost : DEFAULT_HOST;
	cafiles = splitstr(trest_cafiles, ",");

	printf("PANTAHUB_HOST: %s\n", server_host);
	printf("CAFILES: %s\n", trest_cafiles);

	printf("==== Creating trest userclients ...\n");
	userclient = trest_new_tls_from_userpass(
		server_host, atoi(trest_apiport ? trest_apiport : DEFAULT_PORT),
		trest_user ? trest_user : DEFAULT_USER,
		trest_pass ? trest_pass : DEFAULT_USERPASS, cafiles,
		DEFAULT_USERAGENT, NULL);

	badclient = trest_new_tls_from_userpass(
		server_host, atoi(trest_apiport ? trest_apiport : DEFAULT_PORT),
		DEFAULT_USER, DEFAULT_BADPASS, cafiles, DEFAULT_USERAGENT,
		NULL);

	if (!userclient || !badclient) {
		printf(" ERROR creating clients\n");
		rv = 1;
		goto exit;
	}
	printf(" OK\n");

	setup_client(userclient);
	setup_client(badclient);

	printf("==== Testing trest auth_status ...\n");
	status = trest_auth_status(userclient);

	if (status != TREST_AUTH_STATUS_NOTAUTH) {
		printf(" ERROR (status != TREST_AUTH_STATUS_NOTAUTH)\n");
		rv = 2;
		goto exit;
	}
	printf(" OK\n");

	printf("==== make json_request for /auth/login ... \n");
	req = trest_make_request(
		THTTP_METHOD_POST, "/auth/login",
		make_message("{ username: \"%s\", password: \"%s\"}",
			     trest_user ? trest_user : DEFAULT_USER,
			     trest_pass ? trest_pass : DEFAULT_USERPASS));
	if (!req) {
		printf(" ERROR (!req)\n");
		rv = 3;
		goto exit;
	}
	printf(" OK\n");

	printf("==== do json_request ...\n");
	res = trest_do_json_request(userclient, req);
	if (!res) {
		printf(" ERROR (!res)\n");
		rv = 4;
		goto exit;
	}
	printf(" OK\n");

	printf("==== do trest_update_auth (run 1: bad credentials) ...\n");
	auth_status = trest_update_auth(badclient);
	if (auth_status != TREST_AUTH_STATUS_NOTAUTH) {
		printf(" ERROR (!auth_status: %d)\n", auth_status);
		rv = 5;
		goto exit;
	}
	printf(" OK\n");

	printf("==== do trest_update_auth (run 1: update auth) ...\n");
	auth_status = trest_update_auth(userclient);
	if (auth_status != TREST_AUTH_STATUS_OK) {
		printf(" ERROR (!auth_status: %d)\n", auth_status);
		rv = 6;
		goto exit;
	}
	printf(" OK\n");

	for (i = 0; i < 5; i++) {
		sleep(1);
		printf("==== do trest_update_auth (run 2: %d/4) ...\n", i);
		auth_status = trest_update_auth(userclient);
		if (auth_status != TREST_AUTH_STATUS_OK) {
			printf(" ERROR (!auth_status: %d)\n", auth_status);
			rv = 6;
			goto exit;
		}
		printf(" OK\n");
	}

	printf("==== do_json_request: userclient to create device ... \n ");
	req1 = trest_make_request(THTTP_METHOD_POST, "/devices/", "{ }");

	res1 = trest_do_json_request(userclient, req1);
	if (!res1) {
		printf(" ERROR (!res1)\n");
		rv = 7;
		goto exit;
	}
	device_id = get_json_key_value(res1->body, "id", res1->json_tokv,
				       res1->json_tokc);
	device_prn = get_json_key_value(res1->body, "prn", res1->json_tokv,
					res1->json_tokc);
	device_nick = get_json_key_value(res1->body, "nick", res1->json_tokv,
					 res1->json_tokc);
	device_secret = get_json_key_value(res1->body, "secret",
					   res1->json_tokv, res1->json_tokc);

	printf(" OK [deviceid=%s; prn=%s; nick=%s]\n", device_id, device_prn,
	       device_nick);

	printf("==== do trest_update_auth (device credentials) ...\n");

	deviceclient = trest_new_tls_from_userpass(
		server_host, atoi(trest_apiport ? trest_apiport : DEFAULT_PORT),
		device_prn, device_secret, cafiles, DEFAULT_USERAGENT, NULL);

	if (!deviceclient) {
		printf(" ERROR creating device client\n");
		rv = 8;
		goto exit;
	}

	setup_client(deviceclient);

	auth_status = trest_update_auth(deviceclient);
	if (auth_status != TREST_AUTH_STATUS_OK) {
		printf(" ERROR (!auth_status: %d)\n", auth_status);
		rv = 9;
		goto exit;
	}
	printf(" OK\n");

	printf("==== do post initial trail (device: %s) ...\n", device_nick);

	req2 = trest_make_request(
		THTTP_METHOD_POST, "/trails/",
		"{ \"#spec\": \"pantavisor-service-system@1\" }");

	res2 = trest_do_json_request(deviceclient, req2);
	if (!res2) {
		printf(" ERROR (!res2)\n");
		rv = 10;
		goto exit;
	}

	printf("Result %s\n", res2->body);

	printf("==== do get trail steps (device: %s) ...\n", device_nick);

	trail_steps_ep =
		malloc((sizeof(DEVICE_TRAIL_ENDPOINT_FMT) + strlen(device_id)) *
		       sizeof(char));
	sprintf(trail_steps_ep, DEVICE_TRAIL_ENDPOINT_FMT, device_id);

	req3 = trest_make_request(THTTP_METHOD_GET, trail_steps_ep, NULL);

	res3 = trest_do_json_request(deviceclient, req3);
	if (!res3) {
		printf(" ERROR (!res3)\n");
		rv = 11;
		goto exit;
	}
	printf("Result %s\n", res3->body);

	printf("==== post new step to trail as owner (device: %s) ...\n",
	       device_nick);
	req4 = trest_make_request(
		THTTP_METHOD_POST, trail_steps_ep,
		"{\n"
		"  \"rev\": 1,\n"
		"  \"commit-msg\": \"move to myvalue1\",\n"
		"  \"state\": { \"#spec\": \"pantavisor-service-system@1\", \"mytest.json\": { \"test\": \"myvalue1\"} }\n"
		"}");

	res4 = trest_do_json_request(userclient, req4);
	if (!res4) {
		printf(" ERROR (!res4)\n");
		rv = 12;
		goto exit;
	}
	printf("Result %s\n", res4->body);

	printf("==== post new step to trail as owner (device: %s) ...\n",
	       device_nick);
	req4a = trest_make_request(
		THTTP_METHOD_POST, trail_steps_ep,
		"{\n"
		"  \"rev\": 2,\n"
		"  \"commit-msg\": \"move to myvalue2\",\n"
		"  \"state\": { \"#spec\": \"pantavisor-service-system@1\", \"mytest.json\": { \"test\": \"myvalue2\"} }\n"
		"}");

	res4a = trest_do_json_request(userclient, req4a);
	if (!res4a) {
		printf(" ERROR (!res4)\n");
		rv = 121;
		goto exit;
	}
	printf("Result %s\n", res4a->body);

	printf("==== get trail steps as owner (device: %s) ...\n", device_nick);
	req5 = trest_make_request(THTTP_METHOD_GET, trail_steps_ep, 0);

	res5 = trest_do_json_request(userclient, req5);
	if (!res5) {
		printf(" ERROR (!res5)\n");
		rv = 12;
		goto exit;
	}

	printf("Result %s\n", res5->body);
	printf(" OK [steps: %d]\n",
	       jsmnutil_array_count(res5->body, res5->json_tokv));
	iterate_json_array(res5->body, res5->json_tokv, 0,
			   (token_iter_f)print_step, NULL);

	printf("==== get trail steps as device (device: %s) ...\n",
	       device_nick);
	req6 = trest_make_request(THTTP_METHOD_GET, trail_steps_ep, 0);

	res6 = trest_do_json_request(deviceclient, req6);
	if (!res6) {
		printf(" ERROR (!res6)\n");
		rv = 12;
		goto exit;
	}
	printf("Result %s\n", res6->body);
	printf(" OK [steps: %d]\n",
	       jsmnutil_array_count(res5->body, res5->json_tokv));
	iterate_json_array(res6->body, res6->json_tokv, 0,
			   (token_iter_f)print_step, NULL);

exit:
	if (cafiles)
		free(cafiles);
	if (trail_steps_ep)
		free(trail_steps_ep);
	if (device_id)
		free(device_id);
	if (device_prn)
		free(device_prn);
	if (device_nick)
		free(device_nick);
	if (res)
		trest_response_free(res);
	if (req)
		trest_request_free(req);
	if (res1)
		trest_response_free(res1);
	if (req1)
		trest_request_free(req1);
	if (res2)
		trest_response_free(res2);
	if (req2)
		trest_request_free(req2);
	if (res3)
		trest_response_free(res3);
	if (req3)
		trest_request_free(req3);
	if (res4)
		trest_response_free(res4);
	if (req4)
		trest_request_free(req4);
	if (res4a)
		trest_response_free(res4a);
	if (req4a)
		trest_request_free(req4a);
	if (res5)
		trest_response_free(res5);
	if (req5)
		trest_request_free(req5);
	if (res6)
		trest_response_free(res6);
	if (req6)
		trest_request_free(req6);
	if (userclient)
		trest_free(userclient);
	if (deviceclient)
		trest_free(deviceclient);
	if (badclient)
		trest_free(badclient);

	printf("END OF TESTRUN\n");
	return rv;
}
