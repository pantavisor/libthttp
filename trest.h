#include "jsmn/jsmn.h"

typedef enum tcloudc_auth_status {
	TCLOUDC_AUTH_STATUS_OK = 1,
	TCLOUDC_AUTH_STATUS_NOTAUTH,
	TCLOUDC_AUTH_STATUS_ERROR,
	TCLOUDC_AUTH_STATUS_UNKNOWN = 10000,
} tcloudc_auth_status_enum;


typedef enum tcloudc_method {
	TCLOUDC_METHOD_GET = 1,
	TCLOUDC_METHOD_POST,
	TCLOUDC_METHOD_PUT,
	TCLOUDC_METHOD_PATCH,
	TCLOUDC_METHOD_DELETE,
	TCLOUDC_METHOD_HEAD,
	TCLOUDC_METHOD_UNKNOWN = 10000,
} tcloudc_method_enum;

typedef void* tcloudc_client_ptr;
typedef void* tcloudc_request_ptr;
typedef void* tcloudc_response_ptr;

// callback for blob messages. this gets called when
// new data is available with data pointing to the
// received data buffer and data_len having info about
// the data buffer size retrieved.
// Special conditions are treated like the following:
//  - EOF:  data == 0 && data_len == 0
//  - ERROR" data == 0 && data_len == ERROR_CODE
typedef void (*tcloudc_client_cb) (void *user_data,
				unsigned char* data,
				size_t data_len);


tcloudc_client_ptr
tcloudc_client_new_from_userpass(const char* host, int port,
				const char *user,
				const char *pass);

void
tcloudc_client_free (tcloudc_client_ptr ptr);

void
tcloudc_request_free (tcloudc_request_ptr ptr);

void
tcloudc_response_free (tcloudc_response_ptr ptr);

// check auth status if you are just interested in this
tcloudc_auth_status_enum
tcloudc_auth_status (tcloudc_client_ptr ptr);

// update auth tokens if possible. usually tries refresh_token
// against the login endpoint and then other credentials
// if available
tcloudc_auth_status_enum
tcloudc_update_auth (tcloudc_client_ptr ptr);

// make a json request; uses Encoding application/json
// and Accept-Endcoding application/json accordingly
tcloudc_request_ptr
tcloudc_make_json_request (tcloudc_method_enum method,
			char *endpoint_path,
			char **queries,
			char *json_body);

// make a blob request expecting a blob back. this request
// takes a callback function that will be called to pump
// the blob data stream
tcloudc_request_ptr
tcloudc_make_blob_request (tcloudc_method_enum method,
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
tcloudc_response_ptr
tcloud_client_do_request (tcloudc_client_ptr *client,
			tcloudc_request_ptr,
			tcloudc_client_cb callback,
			void* user_data);

tcloudc_response_ptr
tcloud_client_do_json_request (tcloudc_client_ptr *client,
			tcloudc_request_ptr);
