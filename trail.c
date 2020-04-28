/*
 * Copyright (c) 2017 Pantacor Ltd.
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

static char*
parse_strtok (const char *buf, jsmntok_t *tok)
{
	char *v;
	int n;

	if (tok->type != JSMN_STRING) {
		printf ("parse_strtok: error - must be string token (%d) but is (%d)\n", JSMN_STRING, tok->type);
		return NULL;
	}
	n = tok->end - tok->start;
	v = malloc ((n+1) * sizeof(char));
	v[n] = 0;

	strncpy (v, buf + tok->start, n);
	return v;
}

static systemc_object*
parse_object (const char *buf, jsmntok_t *tok)
{
	jsmntok_t **keys, **keys_i;
	systemc_object *obj;

	if (tok->type != JSMN_OBJECT) {
		printf ("parse_object: error - must be object primitive\n");
		return NULL;
	}

	keys_i = keys = jsmnutil_get_object_keys(buf, tok);
	obj = malloc(sizeof(systemc_object));
	obj->prn = NULL;
	obj->filename = NULL;

	while (*keys_i) {
		if (!strncmp ("value", buf + (*keys_i)->start, strlen("value"))) {
			obj->prn = parse_strtok (buf, (*keys_i)+1);
		} else if (!strncmp ("key", buf + (*keys_i)->start, strlen("key"))) {
			obj->filename = parse_strtok (buf, (*keys_i)+1);
		} else {
			printf ("WARNING: unexpected key in object\n");
			goto parse_fail;
		}
		keys_i++;
	}
	goto exit;

parse_fail:
	trail_object_free(obj);
	obj = NULL;

exit:
	jsmnutil_tokv_free(keys);

	return obj;
}

static systemc_volobject*
parse_volobject (const char *buf, jsmntok_t *tok)
{
	jsmntok_t **keys = 0, **keys_i;
	jsmntok_t **vkeys = 0, **vkeys_i;
	systemc_volobject *obj;
	jsmntok_t *valuetok = 0;

	if (tok->type != JSMN_OBJECT) {
		printf ("parse_object: error - must be object primitive\n");
		return NULL;
	}

	keys_i = keys = jsmnutil_get_object_keys(buf, tok);
	obj = malloc(sizeof(systemc_volobject));
	obj->prn = NULL;
	obj->filename = NULL;
	obj->flags = NULL;

	while (*keys_i) {
		if (!strncmp ("value", buf + (*keys_i)->start, strlen("value"))) {
			valuetok = (*keys_i)+1;
		} else if (!strncmp ("key", buf + (*keys_i)->start, strlen("key"))) {
			obj->filename = parse_strtok (buf, (*keys_i)+1);
		} else {
			printf ("WARNING: unexpected key in volobject\n");
			goto parse_fail;
		}
		keys_i++;
	}

	vkeys_i = vkeys = jsmnutil_get_object_keys(buf, valuetok);
	while (*vkeys_i) {
		if (!strncmp ("type", buf + (*vkeys_i)->start, strlen("type"))) {
			obj->flags = parse_strtok (buf, (*vkeys_i)+1);
		} else if (!strncmp ("file", buf + (*vkeys_i)->start, strlen("file"))) {
			obj->prn = parse_strtok (buf, (*vkeys_i)+1);
		} else {
			printf ("WARNING: unexpected key in volobject value object\n");
			goto parse_fail;
		}
		vkeys_i++;
	}
	goto exit;

parse_fail:
	trail_volobject_free(obj);
	obj = NULL;
exit:
	if (vkeys)
		jsmnutil_tokv_free(vkeys);
	if (keys)
		jsmnutil_tokv_free(keys);

	return obj;
}

static systemc_object**
parse_object_arr (const char *buf, jsmntok_t *tok)
{
	jsmntok_t **arr, **arr_i;
	int c,i;
	systemc_object **objv;

	c = jsmnutil_array_count(buf, tok);
	arr_i = arr = jsmnutil_get_array_toks(buf, tok);

	objv = calloc (sizeof(systemc_object*), c+1);
	objv[c] = NULL;

	for (i=0; i<c && *arr_i; i++, arr_i++)
		objv[i] = parse_object(buf, *arr_i);

	jsmnutil_tokv_free(arr);

	return objv;
}

static int
parse_share_arr (const char *buf, jsmntok_t *tok)
{
	jsmntok_t **arr, **arr_i;
	int c,i;
	int share = 0;

	c = jsmnutil_array_count(buf, tok);
	arr_i = arr = jsmnutil_get_array_toks(buf, tok);

	for (i=0; i<c && *arr_i; i++, arr_i++) {
		char *v = parse_strtok (buf, *arr_i);
		if(!v) {
			printf ("WARNING: share array must be all strings\n");
			continue;
		}
		if (!strcmp("NETWORK", v)) {
			share |= SHARE_NET;
		} else if (!strcmp("UTS", v)) {
			share |= SHARE_UTS;
		} else if (!strcmp("IPC", v)) {
			share |= SHARE_IPC;
		} else {
			printf ("WARNING: bad share name %s\n", v);
		}

		free(v);
	}

	jsmnutil_tokv_free(arr);
	return share;
}

static void
parse_systemc (systemc_state *self, const char *buf, jsmntok_t *tok)
{
	self->basev = parse_object_arr(buf, tok);
}

static void
parse_volumes (systemc_state *self, const char *buf, jsmntok_t *tok)
{
	jsmntok_t **arr, **arr_i;
	int c,i;

	c = jsmnutil_array_count(buf, tok);
	arr_i = arr = jsmnutil_get_array_toks(buf, tok);

	self->volumesv = calloc (sizeof(systemc_volobject), c+1);
	self->volumesv[c] = NULL;

	for (i=0; i<c && *arr_i; i++, arr_i++)
		self->volumesv[i] = parse_volobject(buf, *arr_i);

	jsmnutil_tokv_free(arr);
}

static systemc_platform*
parse_platform (const char *buf, jsmntok_t *tok)
{
	jsmntok_t **arr, **arr_i;
	int c,i;
	systemc_platform *obj;

	if (tok->type != JSMN_OBJECT) {
		printf ("parse_platform: error - must be object\n");
		return NULL;
	}

	obj = calloc (sizeof(systemc_platform), 1);
	c = jsmnutil_object_key_count(buf, tok);
	arr_i = arr = jsmnutil_get_object_keys(buf, tok);

	for (i=0; i<c && *arr_i; i++, arr_i++) {
		if (!strncmp ("type", buf + (*arr_i)->start, strlen("type"))) {
			obj->type = parse_strtok (buf, (*arr_i)+1);
		} else if (!strncmp ("parent", buf + (*arr_i)->start, strlen("parent"))) {
			obj->parent = parse_strtok (buf, (*arr_i)+1);
		} else if (!strncmp ("exec", buf + (*arr_i)->start, strlen("exec"))) {
			obj->exec = parse_strtok (buf, (*arr_i)+1);
		} else if (!strncmp ("configs", buf + (*arr_i)->start, strlen("configs"))) {
			obj->configs = parse_object_arr(buf, (*arr_i)+1);
		} else if (!strncmp ("share", buf + (*arr_i)->start, strlen("share"))) {
			obj->share = parse_share_arr(buf, (*arr_i)+1);
		} else {
			printf ("WARNING: unexpected key in platform\n");
			goto parse_fail;
		}
	}

	goto exit;
parse_fail:
	trail_platform_free(obj);
	obj = NULL;

exit:
	jsmnutil_tokv_free(arr);
	return obj;
}


static void
parse_platforms (systemc_state *self, const char *buf, jsmntok_t *tok)
{
	jsmntok_t **arr, **arr_i;
	int c,i;

	c = jsmnutil_object_key_count(buf, tok);
	arr_i = arr = jsmnutil_get_object_keys(buf, tok);

	self->platformsv = calloc (sizeof(systemc_platform), c+1);
	self->platformsv[c] = NULL;

	for (i=0; i<c && *arr_i; i++, arr_i++) {
		self->platformsv[i] = parse_platform(buf, (*arr_i)+1);
		if (!self->platformsv[i]) {
			i--;
			continue;
		}
		self->platformsv[i]->name = parse_strtok (buf, (*arr_i));
	}

	jsmnutil_tokv_free(arr);

}

static void
parse_kernel (systemc_state *self, const char *buf, jsmntok_t *tok)
{
	self->kernel = parse_object(buf, tok);
}

systemc_state*
trail_parse_state (const char *buf, int len)
{
	jsmntok_t *tokv;
	jsmntok_t **key_toks, **ki;
	int tokc, rv;
	systemc_state* state = calloc (sizeof(systemc_state), 1);

	rv = jsmnutil_parse_json(buf, &tokv, &tokc);

	if (rv < 0) {
		printf("ERROR parsing json\n");
		goto exit;
	}

	ki = key_toks = jsmnutil_get_object_keys (buf, tokv);

	while (*ki) {
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

void trail_platform_free (systemc_platform* self)
{
	if(self->name)
		free(self->name);
	if(self->type)
		free(self->type);
	if(self->parent)
		free(self->parent);
	if(self->exec)
		free(self->exec);
	if(self->configs) {
		systemc_object **i;
		for(i = self->configs; *i; i++)
			trail_object_free(*i);
		free(self->configs);
	}

	free(self);
}

void
trail_object_free (systemc_object* self)
{
	if (self->prn)
		free(self->prn);
	if (self->filename)
		free(self->filename);
	free(self);
}

void
trail_volobject_free (systemc_volobject* self)
{
	if (self->prn)
		free(self->prn);
	if (self->filename)
		free(self->filename);
	if (self->flags)
		free(self->flags);
	free(self);
}

void
trail_state_free (systemc_state* self)
{
	if (self->kernel)
		trail_object_free(self->kernel);

	if (self->basev) {
		systemc_object** i = self->basev;
		while (*i) {
			trail_object_free (*i);
			i++;
		}
		free(self->basev);
	}

	if (self->volumesv) {
		systemc_volobject** i = self->volumesv;
		while (*i) {
			trail_volobject_free (*i);
			i++;
		}
		free(self->volumesv);
	}

	if (self->platformsv) {
		systemc_platform** i = self->platformsv;
		while (*i) {
			trail_platform_free (*i);
			i++;
		}
		free(self->platformsv);
	}
	free(self);
}
