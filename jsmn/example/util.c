#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../jsmnutil.h"
#include "../jsmn.h"

/*
 * A small example of jsmn parsing when JSON structure is known and number of
 * tokens is predictable.
 */

static const char *JSON_STRING =
	"{\"user\": \"johndoe\", \"admin\": false, \"uid\": 1000,\n  "
	"\"groups\": [\"users\", \"wheel\", \"audio\", \"video\"]}";

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
	if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
			strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}

int main() {
	int i;
	int r;
	jsmn_parser p;
	jsmntok_t t[128]; /* We expect no more than 128 tokens */

	jsmn_init(&p);
	r = jsmn_parse(&p, JSON_STRING, strlen(JSON_STRING), t, sizeof(t)/sizeof(t[0]));
	if (r < 0) {
		printf("Failed to parse JSON: %d\n", r);
		return 1;
	}

	/* Assume the top-level element is an object */
	if (r < 1 || t[0].type != JSMN_OBJECT) {
		printf("Object expected\n");
		return 1;
	}

	/* Loop over all keys of the root object using jsnmutil */
	jsmntok_t** keys = jsmnutil_get_object_keys (JSON_STRING, t);
	jsmntok_t** keys_i = keys;

	while(*keys_i) {
		if (jsoneq(JSON_STRING, *keys_i, "user") == 0) {
			/* We may use strndup() to fetch string value */
			printf("- User: %.*s\n", (*keys_i+1)->end-(*keys_i+1)->start,
					JSON_STRING + (*keys_i+1)->start);
		} else if (jsoneq(JSON_STRING, *keys_i, "admin") == 0) {
			/* We may additionally check if the value is either "true" or "false" */
			printf("- Admin: %.*s\n", (*keys_i+1)->end - (*keys_i+1)->start,
					JSON_STRING +  (*keys_i+1)->start);
		} else if (jsoneq(JSON_STRING, *keys_i, "uid") == 0) {
			/* We may want to do strtol() here to get numeric value */
			printf("- UID: %.*s\n",  (*keys_i+1)->end - (*keys_i+1)->start,
					JSON_STRING + (*keys_i+1)->start);
		} else if (jsoneq(JSON_STRING, *keys_i, "groups") == 0) {
			int j;
			printf("- Groups:\n");
			if ((*keys_i+1)->type != JSMN_ARRAY) {
				continue; /* We expect groups to be an array of strings */
			}
			for (j = 0; j <  (*keys_i+1)->size; j++) {
				jsmntok_t *g =  (*keys_i+j+2);
				printf("  * %.*s\n", g->end - g->start, JSON_STRING + g->start);
			}
		} else {
			printf("Unexpected key: %.*s\n", (*keys_i)->end-(*keys_i)->start,
					JSON_STRING + (*keys_i)->start);
		}
		keys_i++;
	}

	jsmnutil_tokv_free(keys);
	
	return EXIT_SUCCESS;
}
