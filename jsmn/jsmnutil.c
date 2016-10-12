#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "jsmnutil.h"
#include "jsmn.h"


typedef void (*token_iter_f) (void *data, const char *buf, jsmntok_t* tok, int c);

static int
traverse_token (const char *buf, jsmntok_t* tok)
{
	int i;
	int c=1;
	for (i=0; i < tok->size; i++) {
		c += traverse_token (buf, tok+c);
	}
	return c;
}

// is good for getting elements of any array type token. Just point tok+t to the
// token of type array and it will iterate the direct children of that token
// through travesal the depth first token array.
static int
iterate_json_array(const char *buf, jsmntok_t* tok, token_iter_f func, void *data)
{
	jsmntok_t *s;
	int i;
	int c=0;
	if (tok[0].type != JSMN_ARRAY)
		return JSMNUTIL_ERROR_TOKTYPE;

	c++;
	for(i=0; i < tok->size; i++) {
		func(data, buf, tok+c, i);
		c+=traverse_token (buf, tok+c);
	}

	return JSMNUTIL_OK;
}

// is good for getting elements of any array type token. Just point tok+t to the
// token of type array and it will iterate the direct children of that token
// through travesal the depth first token array.
static int
iterate_json_keys(const char *buf, jsmntok_t* tok, token_iter_f func, void *data)
{
	jsmntok_t *s;
	int i;
	int c=0;

	if (tok[c].type != JSMN_OBJECT)
		return JSMNUTIL_ERROR_TOKTYPE;

	c++;
	for(i=0; i < get_json_object_key_count(buf, tok); i++) {
		printf ("Before traverse: %d %d\n", c, (tok+c)->size);
		func(data, buf, tok+c, i);
		c += traverse_token (buf, tok+c);
		printf ("after traverse: %d\n", c);
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
tok_arr_append_cb(void *data, const char* buf, jsmntok_t *tok, int c)
{
	jsmntok_t **arr = (jsmntok_t **) data;
	// XXX: figure get_array_toks without the +1 offset.

	arr[c] = tok;
}


int
get_json_array_count(const char *buf, jsmntok_t* tok)
{
	if (tok[0].type != JSMN_ARRAY) {
		printf ("provided tok is not of type JSNM_ARRAY\n");
		return -1;
	}

	return tok[0].size;
}

jsmntok_t**
jsmnutil_get_array_toks (const char *buf, jsmntok_t *tok)
{
	jsmntok_t** arr;

	if(tok->type != JSMN_ARRAY) {
		printf ("ERROR: jsmnutil_get_array_toks expects JSMN_ARRAY(%d) tok as input; found: %d\n",
			JSMN_ARRAY, tok->type);
		return NULL;
	}

	arr = malloc(sizeof(jsmntok_t*) * (tok->size + 1));
	arr[tok->size] = NULL; // NULL terminated

	iterate_json_array(buf, tok, tok_arr_append_cb, arr);

	return arr;
}

int
get_json_object_key_count(const char *buf, jsmntok_t* tok)
{
	if (tok[0].type != JSMN_OBJECT) {
		printf ("provided tok is not of type JSNM_ARRAY\n");
		return -1;
	}

	return tok->size;
}

jsmntok_t**
jsmnutil_get_object_keys (const char *buf, jsmntok_t *tok)
{
	jsmntok_t** arr;
	int c;

	if(tok->type != JSMN_OBJECT) {
		printf ("ERROR: jsmnutil_get_array_toks expects JSMN_OBJECT(%d) tok as input; found: %d\n",
			JSMN_ARRAY, tok->type);
		return NULL;
	}

	c = get_json_object_key_count(buf, tok);
	printf ("Malloc keys: %d\n",c);
	arr = malloc(sizeof(jsmntok_t*) * (c + 1));
	arr[c] = NULL; // NULL terminated

	iterate_json_keys(buf, tok, tok_arr_append_cb, arr);

	return arr;
}

jsmntok_t*
jsmnutil_get_object_key_value (const char *buf, jsmntok_t *tok)
{
	// values are always right next to the key...
	return tok+1;
}

void
jsmnutil_tokv_free(jsmntok_t** tok)
{
	if (!tok)
		return;

	// do not free tokens as they are managed by
	// token array memory blocked created during
	// parsing
	free (tok);
}
