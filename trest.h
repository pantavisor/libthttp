#include "jsmn/jsmn.h"

typedef enum trest_auth_status {
	TREST_AUTH_STATUS_OK = 1,
	TREST_AUTH_STATUS_NOTAUTH,
	TREST_AUTH_STATUS_ERROR,
	TREST_AUTH_STATUS_UNKNOWN = 10000,
} trest_auth_status_enum;


typedef enum trest_method {
	TREST_METHOD_GET = 1,
	TREST_METHOD_POST,
	TREST_METHOD_PUT,
	TREST_METHOD_PATCH,
	TREST_METHOD_DELETE,
	TREST_METHOD_HEAD,
	TREST_METHOD_UNKNOWN = 10000,
} trest_method_enum;

typedef void* trest_ptr;
typedef void* trest_request_ptr;
typedef void* trest_response_ptr;

// callback for blob messages. this gets called when
// new data is available with data pointing to the
// received data buffer and data_len having info about
// the data buffer size retrieved.
// Special conditions are treated like the following:
//  - EOF:  data == 0 && data_len == 0
//  - ERROR" data == 0 && data_len == ERROR_CODE
typedef void (*trest_cb) (void *user_data,
				unsigned char* data,
				size_t data_len);


trest_ptr
trest_new_from_userpass(const char* host, int port,
				const char *user,
				const char *pass);

void
trest_free (trest_ptr ptr);

void
trest_request_free (trest_request_ptr ptr);

void
trest_response_free (trest_response_ptr ptr);

// check auth status if you are just interested in this
trest_auth_status_enum
trest_auth_status (trest_ptr ptr);

// update auth tokens if possible. usually tries refresh_token
// against the login endpoint and then other credentials
// if available. usually needs to be called once to get
// initial auth token, but this behaviour depends on the
// credential type and backend implementation.
trest_auth_status_enum
trest_update_auth (trest_ptr ptr);

// make a json request; uses Encoding application/json
// and Accept-Endcoding application/json accordingly
trest_request_ptr
trest_make_json_request (trest_method_enum method,
			char *endpoint_path,
			char **queries,
			char *json_body);

// make a blob request expecting a blob back. this request
// takes a callback function that will be called to pump
// the blob data stream
trest_request_ptr
trest_make_blob_request (trest_method_enum method,
			char *endpoint_path,
			char **queries,
			char *json_body);


// execute the request.
// XXX: later or think about:
//   -- this will autoperform redirects
//   -- if they are going to the same service. The service
//   -- endpoint prefix is determined through a setting that
//   -- can be tweaked against the _request objects. By
//   -- default the client uses.
trest_response_ptr
tcloud_client_do_request (trest_ptr client,
			trest_request_ptr ptr,
			trest_cb callback,
			void* user_data);

trest_response_ptr
tcloud_client_do_json_request (trest_ptr *client,
			trest_request_ptr);
