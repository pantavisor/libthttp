#include <time.h>

#include "jsmn/jsmn.h"

typedef struct _systemc_object {
	char *abrn;
	char *filename;
	int flags;
} systemc_object;

typedef struct _systemc_platform {
	char *type;
	char *parent;
	char *exec;
	char **share;

	systemc_object **configs;
	
	int flags;
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

	char *committer;
	char *commit_msg; // commit-msg

	time_t step_time;
	time_t progress_time;

	systemc_object *base;
	systemc_object *kernel;
	systemc_object **volumesv;
	systemc_platform **platformsv;
} systemc_state;

systemc_state* trail_parse_state (const char *buf, int len);

systemc_state* trail_parse_state_from_file (const char *filename);

