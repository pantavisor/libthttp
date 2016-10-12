#include "jsmn.h"

enum
{
	JSMNUTIL_OK=0,
	JSMNUTIL_ERROR_TOKTYPE=1
};
	

/* count of keys inside a JSMN_OBJECT */
int
get_json_object_key_count(const char *buf, jsmntok_t* tok);

/* count of keys inside a JSMN_ARRAY */
int
get_json_array_count(const char *buf, jsmntok_t* tok);

/*
 * create a new array of jsnmtok_t pointers to the
 * array sub elements; needs to be freed using
 * jsmnutil_tokv_free
 */
jsmntok_t**
jsmnutil_get_array_toks (const char *buf, jsmntok_t *tok);

/*
 * create a new array of jsnmtok_t pointers; needs
 * to be freed using jsmnutil_tokv_free
 */
jsmntok_t**
jsmnutil_get_object_keys (const char *buf, jsmntok_t *tok);

/* get value for a given key */
jsmntok_t*
jsmnutil_get_object_key_value (const char *buf, jsmntok_t *tok);

/* free NULL terminated pointer array */
void
jsmnutil_tokv_free(jsmntok_t** tok);
