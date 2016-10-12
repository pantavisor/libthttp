#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trail.h"
#include "jsmn/jsmnutil.h"

static void
parse_rev (systemc_state *self, const char *buf, jsmntok_t *tok)
{
	int n;
	char *tmp;
	if (tok->type != JSMN_PRIMITIVE) {
		printf ("parse_rev: error - must be numeric primitive\n");
		return;
	}
	n = tok->end - tok->start;
	tmp = malloc (sizeof(char) * n+1);
	strncpy (tmp, buf+tok->start, n);
	tmp[n] = 0;
	self->rev = atoi(tmp);
	free(tmp);
}

static void
parse_systemc (systemc_state *self, const char *buf, jsmntok_t *tok)
{
	printf ("parse_systemc: start\n");

}

static void
parse_volumes (systemc_state *self, const char *buf, jsmntok_t *tok)
{
	printf ("parse_volumes: start\n");
}

static void
parse_platforms (systemc_state *self, const char *buf, jsmntok_t *tok)
{
	printf ("parse_platforms: start\n");
}

static void
parse_kernel (systemc_state *self, const char *buf, jsmntok_t *tok)
{
	printf ("parse_kernel: start\n");
}

systemc_state*
trail_parse_state (const char *buf, int len)
{
	jsmntok_t *tokv;
	jsmntok_t **key_toks, **ki;
	int tokc, rv;
	systemc_state* state = malloc (sizeof(systemc_state));

	rv = jsmnutil_parse_json(buf, &tokv, &tokc);

	if (rv < 0) {
		printf("ERROR parsing json\n");
		goto exit;
	}

	ki = key_toks = jsmnutil_get_object_keys (buf, tokv);

	while (*ki) {
		jsmntok_t *keytok = *ki;
		int n = ((*ki)->end - (*ki)->start);
		char *key;

		if (!strncmp("rev", buf+(*ki)->start, strlen("rev")))
			parse_rev(state, buf, *ki + 1);
		else if (!strncmp("systemc", buf+(*ki)->start, strlen("systemc")))
			parse_systemc(state, buf, *ki + 1);
		else if (!strncmp("volumes", buf+(*ki)->start, strlen("volumes")))
			parse_volumes(state, buf, *ki + 1);
		else if (!strncmp("platforms", buf+(*ki)->start, strlen("platforms")))
			parse_platforms(state, buf, *ki + 1);
		else if (!strncmp("kernel", buf+(*ki)->start, strlen("kernel")))
			parse_kernel(state, buf, *ki + 1);
		else
			goto warnkey;

		goto next;

	warnkey:
		key = malloc(sizeof(char) * n+1);
		key[n] = 0;
		strncpy (key, buf+(*ki)->start, n);
		printf("WARNING: unrecognized state key %s\n", key);
		free(key);

	next:
		ki++;
	}

	free (key_toks);
exit:
	free (tokv);
	return state;
}
