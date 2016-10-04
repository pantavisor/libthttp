#include "stdio.h"
#include "trest.h"

#define DEFAULT_HOST "localhost"
#define DEFAULT_PORT 12365
#define DEFAULT_USER "user1"
#define DEFAULT_PASS "user1"

int main (char **argv, int argc) {
	int rv = 0;
	trest_ptr client = 0;
	trest_response_ptr res = 0;
	trest_request_ptr req = 0;

	printf("Creating trest client ...");
	client = trest_new_from_userpass(DEFAULT_HOST, DEFAULT_PORT,
					 DEFAULT_USER, DEFAULT_PASS);

	if (!client) {
		printf (" ERROR\n");
		rv = 1;
		goto exit;
	}
	printf(" OK\n");


	printf("Testing trest auth_status ...");
	trest_auth_status_enum status =
		trest_auth_status(client);

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
				  DEFAULT_PASS
				  "\" }");
	if (!req) {
		printf (" ERROR (!req)\n");
		rv = 3;
		goto exit;
	}
	printf(" OK\n");


	printf("do json_request ...");
	res = trest_do_json_request(client,
				    req);
	if (!res) {
		printf (" ERROR (!res)\n");
		rv = 4;
		goto exit;
	}
	printf(" OK\n");


	printf("do trest_update_auth ...");
	trest_auth_status_enum auth_status = trest_update_auth (client);
	if (auth_status != TREST_AUTH_STATUS_OK) {
		printf (" ERROR (!auth_status: %d)\n", auth_status);
		rv = 5;
		goto exit;
	}
	printf(" OK\n");

exit:
	if (res)
		trest_response_free(res);
	if (req)
		trest_request_free(req);
	if (client)
		trest_free (client);

	printf("END OF TESTRUN\n");
	return rv;
}
