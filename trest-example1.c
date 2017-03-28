#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trest.h"
#include "jsmn/jsmnutil.h"

#define DEFAULT_HOST "localhost"
#define DEFAULT_PORT 12365
#define DEFAULT_USER "user1"
#define DEFAULT_USERPASS "user1"
#define DEFAULT_BADPASS "badpassword"
#define DEFAULT_DEVICEPASS "device1"

#define DEVICE_TRAIL_ENDPOINT_FMT "/api/trails/%s/steps"

typedef void (*token_iter_f) (void *data, char *buf, jsmntok_t* tok, int c);

static int
traverse_token (char *buf, jsmntok_t* tok, int t)
{
	int i;
	int c;
	c=t;
	for (i=0; i < tok[t].size; i++) {
		c = traverse_token (buf, tok, c+1);
	}
	return c;
}

// is good for getting elements of any array type token. Just point tok+t to the
// token of type array and it will iterate the direct children of that token
// through travesal the depth first token array.
static int
iterate_json_array(char *buf, jsmntok_t* tok, int t, token_iter_f func, void *data)
{
	jsmntok_t *s;
	int i;
	int c;
	if (tok[t].type != JSMN_ARRAY) {
		printf("iterare_json_array: token not array");
		return -1;
	}

	c = t;
	for(i=0; i < tok->size; i++) {
		func(data, buf, tok, c+1);
		c = traverse_token (buf, tok, c+1);
	}
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

static void
print_step (void *data, char* buf, jsmntok_t *tok, int c)
{
	int n = (tok+c)->end - (tok+c)->start;
	char *s = malloc (sizeof (char) * n+2);
	buf[n+1]=0;
	strncpy(s, buf + (tok+c)->start, n+2);
	printf ("TOKEN: start=%d, end=%d, buf=%s\n",
		(tok+c)->start, (tok+c)->end, s);
	free(s);
}

int main (char **argv, int argc)
{
	int rv = 0;
	int i;
	char *device_prn = 0, *device_id = 0, *device_nick = 0;
	char *trail_steps_ep = 0;
	trest_ptr badclient = 0, deviceclient = 0, userclient = 0;
	trest_response_ptr res = 0, res1 = 0, res2 = 0, res3 = 0, res4 = 0,
		res4a = 0, res5 = 0, res6 = 0;
	trest_request_ptr req = 0, req1 = 0, req2 = 0, req3 = 0, req4 = 0,
		req4a = 0, req5 = 0, req6 = 0;
	const char *server_host;

	server_host = getenv ("PANTAHUB_HOST") ? getenv ("PANTAHUB_HOST") :  DEFAULT_HOST;

	printf ("PANTAHUB_HOST: %s\n", server_host);
	printf("Creating trest userclients ...");
	userclient = trest_new_from_userpass(server_host, DEFAULT_PORT,
					     DEFAULT_USER, DEFAULT_USERPASS);

	badclient = trest_new_from_userpass(server_host, DEFAULT_PORT,
					    DEFAULT_USER, DEFAULT_BADPASS);


	if (!userclient || !badclient) {
		printf (" ERROR creating clients\n");
		rv = 1;
		goto exit;
	}
	printf(" OK\n");


	printf("Testing trest auth_status ...");
	trest_auth_status_enum status =
		trest_auth_status(userclient);

	if (status != TREST_AUTH_STATUS_NOTAUTH) {
		printf (" ERROR (status != TREST_AUTH_STATUS_NOTAUTH)\n");
		rv = 2;
		goto exit;
	}
	printf(" OK\n");


	printf("make json_request for /api/auth/login ...");
	req = trest_make_request (TREST_METHOD_POST,
				  "/api/auth/login",
				  0, // queries
				  0, // headers
				  "{ username: \""
				  DEFAULT_USER
				  "\", password: \""
				  DEFAULT_USERPASS
				  "\" }");
	if (!req) {
		printf (" ERROR (!req)\n");
		rv = 3;
		goto exit;
	}
	printf(" OK\n");


	printf("do json_request ...");
	res = trest_do_json_request(userclient,
				    req);
	if (!res) {
		printf (" ERROR (!res)\n");
		rv = 4;
		goto exit;
	}
	printf(" OK\n");


	printf("do trest_update_auth (run 1: bad credentials) ...");
	trest_auth_status_enum auth_status = trest_update_auth (badclient);
	if (auth_status != TREST_AUTH_STATUS_NOTAUTH) {
		printf (" ERROR (!auth_status: %d)\n", auth_status);
		rv = 5;
		goto exit;
	}
	printf(" OK\n");

	printf("do trest_update_auth (run 1: user credentials) ...");
	auth_status = trest_update_auth (userclient);
	if (auth_status != TREST_AUTH_STATUS_OK) {
		printf (" ERROR (!auth_status: %d)\n", auth_status);
		rv = 6;
		goto exit;
	}
	printf(" OK\n");

	for (i=0; i< 5; i++) {
		sleep(1);
		printf("do trest_update_auth (run 2: %d/4) ...", i);
		auth_status = trest_update_auth (userclient);
		if (auth_status != TREST_AUTH_STATUS_OK) {
			printf (" ERROR (!auth_status: %d)\n", auth_status);
			rv = 6;
			goto exit;
		}
		printf(" OK\n");
	}


	printf("do_json_request: userclient to create device ... ");
	req1 = trest_make_request (TREST_METHOD_POST,
				   "/api/devices/",
				   0, // queries
				   0, // headers
				   "{ \"secret\": \""
				   DEFAULT_DEVICEPASS
				   "\" }");

	res1 = trest_do_json_request(userclient,
				     req1);
	if (!res1) {
		printf (" ERROR (!res1)\n");
		rv = 7;
		goto exit;
	}
	device_id = get_json_key_value (res1->body, "id", res1->json_tokv,
					res1->json_tokc);
	device_prn = get_json_key_value (res1->body, "prn", res1->json_tokv,
					  res1->json_tokc);
	device_nick = get_json_key_value (res1->body, "nick", res1->json_tokv,
					  res1->json_tokc);

	printf(" OK [deviceid=%s; prn=%s; nick=%s]\n", device_id, device_prn, device_nick);

	printf("do trest_update_auth (device credentials) ...");

	deviceclient = trest_new_from_userpass(server_host, DEFAULT_PORT,
					       device_prn, DEFAULT_DEVICEPASS);

	if (!deviceclient) {
		printf (" ERROR creating device client\n");
		rv = 8;
		goto exit;
	}

	auth_status = trest_update_auth (deviceclient);
	if (auth_status != TREST_AUTH_STATUS_OK) {
		printf (" ERROR (!auth_status: %d)\n", auth_status);
		rv = 9;
		goto exit;
	}
	printf(" OK\n");


	printf("do post initial trail (device: %s) ...", device_nick);

	req2 = trest_make_request (TREST_METHOD_POST,
				   "/api/trails/",
				   0, // queries
				   0, // headers
				   "{ \"mydata\": \"myvalue\" }");

	res2 = trest_do_json_request(deviceclient,
				     req2);
	if (!res2) {
		printf (" ERROR (!res2)\n");
		rv = 10;
		goto exit;
	}

	printf(" OK\n");


	printf("do get trail steps (device: %s) ...", device_nick);

	trail_steps_ep = malloc ((sizeof(DEVICE_TRAIL_ENDPOINT_FMT)
				  + strlen (device_id)) * sizeof(char));
	sprintf(trail_steps_ep, DEVICE_TRAIL_ENDPOINT_FMT, device_id);

	req3 = trest_make_request (TREST_METHOD_GET,
				   trail_steps_ep,
				   0, // queries
				   0, // headers
				   NULL);

	res3 = trest_do_json_request(deviceclient,
				     req3);
	if (!res3) {
		printf (" ERROR (!res3)\n");
		rv = 11;
		goto exit;
	}
	printf(" OK\n");

#define COMMIT_MSG_TMPL "{\n" \
		"  \"rev\": 1,\n"				    \
		"  \"commit-msg\": \"large commit message: %s\",\n" \
		"  \"state\": { \"mydata\": \"myvalue1\" }\n"	    \
		"}"

	char *commit_msg = malloc (sizeof(char) * 4096);
	memset(commit_msg, '\0', sizeof(char) * 4096);
	memset(commit_msg, 'a', sizeof(char) * 4000);
	char *str = malloc (strlen (COMMIT_MSG_TMPL) * sizeof(char) + strlen (commit_msg));
	sprintf(str, COMMIT_MSG_TMPL, commit_msg);

	printf("post new step to trail as owner (device: %s) ...", device_nick);
	req4 = trest_make_request (TREST_METHOD_POST,
				   trail_steps_ep,
				   0, // queries
				   0, // headers
				   str);

	res4 = trest_do_json_request(userclient,
				     req4);
	if (!res4) {
		printf (" ERROR (!res4)\n");
		rv = 12;
		goto exit;
	}
	printf(" OK\n");


	printf("post new step to trail as owner (device: %s) ...", device_nick);
	req4a = trest_make_request (TREST_METHOD_POST,
				    trail_steps_ep,
				    0, // queries
				    0, // headers
				    "{\n"
				    "  \"rev\": 2,\n"
				    "  \"commit-msg\": \"move to myvalue2\",\n"
				    "  \"state\": { \"mydata\": \"myvalue2\" }\n"
				    "}");

	res4a = trest_do_json_request(userclient,
				      req4a);
	if (!res4a) {
		printf (" ERROR (!res4)\n");
		rv = 121;
		goto exit;
	}
	printf(" OK\n");


	printf("get trail steps as owner (device: %s) ...", device_nick);
	req5 = trest_make_request (TREST_METHOD_GET,
				   trail_steps_ep,
				   0, // queries
				   0, // headers
				   0);

	res5 = trest_do_json_request(userclient,
				     req5);
	if (!res5) {
		printf (" ERROR (!res5)\n");
		rv = 12;
		goto exit;
	}
	printf(" OK [steps: %d]\n", jsmnutil_array_count (res5->body, res5->json_tokv));
	iterate_json_array (res5->body, res5->json_tokv, 0, (token_iter_f) print_step, NULL);

	printf("get trail steps as device (device: %s) ...", device_nick);
	req6 = trest_make_request (TREST_METHOD_GET,
				   trail_steps_ep,
				   0, // queries
				   0, // headers
				   0);

	res6 = trest_do_json_request(deviceclient,
				     req6);
	if (!res6) {
		printf (" ERROR (!res6)\n");
		rv = 12;
		goto exit;
	}
	printf(" OK [steps: %d]\n", jsmnutil_array_count (res5->body, res5->json_tokv));
	iterate_json_array (res6->body, res6->json_tokv, 0, (token_iter_f) print_step, NULL);

exit:
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
	if (str)
		free(str);
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
		trest_free (userclient);
	if (deviceclient)
		trest_free (deviceclient);
	if (badclient)
		trest_free (badclient);

	printf("END OF TESTRUN\n");
	return rv;
}
