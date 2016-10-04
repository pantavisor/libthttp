#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trest.h"

#define DEFAULT_HOST "localhost"
#define DEFAULT_PORT 12365
#define DEFAULT_USER "user1"
#define DEFAULT_USERPASS "user1"
#define DEFAULT_BADPASS "badpassword"
#define DEFAULT_DEVICE "abrn:::devices:/57f41438b376a825cf000001"
#define DEFAULT_DEVICEPASS "device1"

static char*
get_json_string_value(char *buf, char *key, jsmntok_t* tok, int tokc)
{
	int i;
	int t=-1;

	for(i=0; i<tokc; i++) {
		int n = tok[i].end - tok[i].start;
		if (tok[i].type == JSMN_STRING
		    && !strncmp(buf + tok[i].start, key, n)) {
			t=1;
		} else if (t==1 && tok[i].type == JSMN_STRING) {
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

int main (char **argv, int argc) {
	int rv = 0;
	char *device_id = 0;
	trest_ptr userclient = 0;
	trest_ptr deviceclient = 0;
	trest_ptr badclient = 0;
	trest_response_ptr res = 0;
	trest_request_ptr req = 0;
	trest_response_ptr res1 = 0;
	trest_request_ptr req1 = 0;

	printf("Creating trest userclients ...");
	userclient = trest_new_from_userpass(DEFAULT_HOST, DEFAULT_PORT,
					     DEFAULT_USER, DEFAULT_USERPASS);

	badclient = trest_new_from_userpass(DEFAULT_HOST, DEFAULT_PORT,
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

	for (int i=0; i< 5; i++) {
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


	printf("do_json_request: userclient to create device ... \n");
	req1 = trest_make_request (TREST_METHOD_POST,
				   "/api/devices/",
				   0, // queries
				   0, // headers
				   "{ secret: \""
				   DEFAULT_DEVICEPASS
				   "\" }");

	res1 = trest_do_json_request(userclient,
				    req1);
	if (!res1) {
		printf (" ERROR (!res)\n");
		rv = 7;
		goto exit;
	}
	device_id = get_json_string_value (res1->body, "id", res1->json_tokv,
					   res1->json_tokc);
	printf(" OK [deviceid=%s]\n", device_id);

	printf("do trest_update_auth (device credentials) ...");

	deviceclient = trest_new_from_userpass(DEFAULT_HOST, DEFAULT_PORT,
					       DEFAULT_DEVICE, DEFAULT_DEVICEPASS);

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



exit:

	if (device_id)
		free(device_id);
	if (res)
		trest_response_free(res);
	if (req)
		trest_request_free(req);
	if (userclient)
		trest_free (userclient);
	if (badclient)
		trest_free (badclient);

	printf("END OF TESTRUN\n");
	return rv;
}
