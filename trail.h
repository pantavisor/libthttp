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
#include <time.h>

#include "jsmn/jsmn.h"

typedef struct _systemc_object {
	char *prn;
	char *filename;
} systemc_object;

typedef struct _systemc_volobject {
	char *prn;
	char *filename;
	char *flags;
} systemc_volobject;

enum {
	SHARE_NET = 1,
	SHARE_UTS = 2,
	SHARE_IPC = 4
};

typedef struct _systemc_platform {
	char *name;
	char *type;
	char *parent;
	char *exec;

	int share;

	systemc_object **configs;
} systemc_platform;

typedef struct _systemc_step
{
	int rev;

	char *trail_id; // trail-id
	char *owner;
	char *device;

	char *committer;
	char *commit_msg; // commit-msg

	time_t step_time;
	time_t progress_time;
} systemc_step;

typedef struct _systemc_state
{
	int rev;

	char *trail_id; // trail-id

	systemc_object **basev;
	systemc_object *kernel;
	systemc_volobject **volumesv;
	systemc_platform **platformsv;
} systemc_state;

systemc_state* trail_parse_state (const char *buf, int len);

systemc_state* trail_parse_state_from_file (const char *filename);

void trail_object_free (systemc_object* self);
void trail_volobject_free (systemc_volobject* self);
void trail_platform_free (systemc_platform* self);
void trail_state_free (systemc_state* self);

