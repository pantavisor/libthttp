#include "stdio.h"
#include "trest.h"

#define DEFAULT_HOST "localhost"
#define DEFAULT_PORT 12365
#define DEFAULT_USER "user1"
#define DEFAULT_PASS "pass"

int main (char **argv, int argc) {
	trest_ptr client;


	printf("Creating trest client ...");
	client = trest_new_from_userpass(DEFAULT_HOST, DEFAULT_PORT,
					DEFAULT_USER, DEFAULT_PASS);

	if (!client) {
		printf (" ERROR\n");
		return 1;
	}
	printf(" OK\n");

	trest_free (client);

	return 0;
}
