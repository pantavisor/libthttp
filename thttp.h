#include "thttp-enums.h"

#ifndef DEBUG
#define DEBUG 0
#endif

typedef struct thttp_request {
	t_thttp_method method;
	t_thttp_proto proto;
	t_thttp_proto_version proto_version;
	int use_tls;
	char *host;
	int port;
	char *path;
	char **headers;
	char *body;
	char *body_content_type;
} t_thttp_request;

typedef struct thttp_response {
	t_thttp_method method;
	t_thttp_proto proto;
	t_thttp_proto_version proto_version;
	char **headers;
	char *body;
	t_thttp_status code;
} t_thttp_response;


t_thttp_response* thttp_request_do (t_thttp_request* req);

t_thttp_request* thttp_request_new_0 ();
void thttp_request_free (t_thttp_request* ptr);
void thttp_response_free (t_thttp_response* ptr);

t_thttp_status thttp_string_to_status (char *string);
const char* thttp_status_to_string (t_thttp_status status);

t_thttp_proto thttp_string_to_proto (char *string);
const char* thttp_proto_to_string (t_thttp_proto proto);

t_thttp_proto_version thttp_string_to_proto_version (char* string);
const char* thttp_proto_version_to_string (t_thttp_proto_version proto);

t_thttp_method
thttp_string_to_method (char *string);

const char*
thttp_method_to_string (t_thttp_proto proto);
