
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "thttp.h"
#include "tinyhttp/http.h"

#define BUF_BLOCKSIZE 1024

struct http_response_parser {
	t_thttp_response *out;
	size_t body_at;
	size_t body_bufsize;
	size_t headers_at;
	size_t headers_bufsize;
};

static unsigned char*
buf_nappend (unsigned char *buf, size_t *at, const unsigned char* append, size_t *bufsize, size_t n)
{
	if (*at + n >= *bufsize) {
		*bufsize += sizeof(char) * BUF_BLOCKSIZE;
		buf = realloc (buf, *bufsize);
	}
	strncpy (buf + *at, append, n);
	*at+=n;
	buf[*at]=0;
	return buf;
}

static unsigned char*
buf_append (unsigned char *buf, size_t *at, const unsigned char* append, size_t *bufsize)
{
	buf_nappend(buf, at, append, bufsize, strlen(append));
	return buf;
}

static unsigned char*
buf_append_int(unsigned char *buf, size_t *at, int append, size_t *bufsize)
{
	unsigned char append_buf[256];
	sprintf(append_buf, "%d", append);
	buf = buf_append (buf, at, append_buf, bufsize);
	return buf;
}

static size_t
make_http_req (t_thttp_request *req, unsigned char **buf)
{
	size_t bufsize = BUF_BLOCKSIZE * sizeof(unsigned char);
	size_t at = 0;
	char **headers = req->headers;

	// allocate at first and set first char to 0
	*buf = malloc (bufsize);
	**buf = 0;

	// append METHOD /PATH/ HTTP/VERSION line
	*buf = buf_append (*buf, &at, thttp_method_to_string (req->method), &bufsize);
	*buf = buf_append (*buf, &at, " ", &bufsize);
	*buf = buf_append (*buf, &at, req->path, &bufsize);
	*buf = buf_append (*buf, &at, " ", &bufsize);
	*buf = buf_append (*buf, &at, thttp_proto_to_string (req->proto), &bufsize);
	*buf = buf_append (*buf, &at, "/", &bufsize);
	*buf = buf_append (*buf, &at, thttp_proto_version_to_string (req->proto), &bufsize);
	*buf = buf_append (*buf, &at, "\r\n", &bufsize);

	// Host: hostname:port header line goes first (even for HTTP/1.0)
	*buf = buf_append (*buf, &at, "Host: ", &bufsize);
	*buf = buf_append (*buf, &at, req->host, &bufsize);
 	*buf = buf_append (*buf, &at, ":", &bufsize);
	*buf = buf_append_int (*buf, &at, req->port, &bufsize);
	*buf = buf_append (*buf, &at, "\r\n", &bufsize);

	// append headers; one each line!
	while (headers && *headers) {
		*buf = buf_append (*buf, &at, *headers, &bufsize);
		*buf = buf_append (*buf, &at, "\r\n", &bufsize);
		headers++;
	}
	// end of headers; add a CRLF
	if (req->body) {
		*buf = buf_append (*buf, &at, "Content-Length: ", &bufsize);
		*buf = buf_append_int (*buf, &at, strlen (req->body), &bufsize);
		*buf = buf_append (*buf, &at, "\r\n", &bufsize);
		*buf = buf_append (*buf, &at, "Content-Type: ", &bufsize);
		*buf = buf_append (*buf, &at, req->body_content_type, &bufsize);
		*buf = buf_append (*buf, &at, "\r\n", &bufsize);
		*buf = buf_append (*buf, &at, "\r\n", &bufsize);
		*buf = buf_append (*buf, &at, req->body, &bufsize);
	}
	// GOGOGO
	*buf = buf_append (*buf, &at, "\r\n", &bufsize);

	return at;
}


static void*
_response_realloc(void* opaque, void* ptr, int size)
{
	struct http_response_parser* parser = (struct http_response_parser*) opaque;
	return realloc(ptr, size);
}

static void
_response_body(void* opaque, const char* data, int size)
{
	struct http_response_parser* parser = (struct http_response_parser*) opaque;
	parser->out->body = buf_nappend (parser->out->body, &parser->body_at, data, &parser->body_bufsize, size);
//	response->body.insert(response->body.end(), data, data + size);
}

static void
_response_header(void* opaque, const char* ckey, int nkey, const char* cvalue, int nvalue)
{
	struct http_response_parser* parser = (struct http_response_parser*) opaque;

	if (parser->headers_at + 1 >= parser->headers_bufsize) {
		parser->headers_bufsize += sizeof(char*) * BUF_BLOCKSIZE;
		parser->out->headers = realloc(parser->out->headers, parser->headers_bufsize);
	}

	parser->out->headers[parser->headers_at] = calloc (sizeof(char) * (nvalue + nkey) + sizeof(": \0"), 1);
	strncat(parser->out->headers[parser->headers_at], ckey, nkey);
	strcat(parser->out->headers[parser->headers_at], ": ");
	strncat(parser->out->headers[parser->headers_at], cvalue, nvalue);

	parser->out->headers[++parser->headers_at] = 0;
}

static void
_response_code(void* opaque, int code)
{
	struct http_response_parser* parser = (struct http_response_parser*) opaque;
	parser->out->code = code;
}

static const struct http_funcs _http_response_funcs = {
    _response_realloc,
    _response_body,
    _response_header,
    _response_code,
};


t_thttp_request*
thttp_request_new_0 ()
{
	return calloc (sizeof(t_thttp_request), 1);
}

void
thttp_request_free (t_thttp_request* ptr)
{
	free (ptr);
}

void
thttp_response_free (t_thttp_response* ptr)
{
	char **headers_i = ptr->headers;

	while (headers_i && *headers_i) {
		free(*headers_i);
		headers_i++;
	}
	free(ptr->headers);
	free(ptr->body);
	free (ptr);
}

t_thttp_response*
thttp_request_do (t_thttp_request* req)
{
	int ret, len, server_fd;
	unsigned char *reqbuf = 0;
	unsigned char resbuf[1024];
	struct sockaddr_in server_addr;
	struct hostent *server_host;
	struct http_response_parser parser;

	memset (&parser, 0, sizeof (parser));
	parser.out = calloc(sizeof(t_thttp_response), 1);

	if (DEBUG)
		printf ("Connecting to tcp/%s/%4d...", req->host,
			req->port);

	fflush (stdout);

	if ((server_host = gethostbyname (req->host)) == NULL)
	{
		printf ("ERROR: failed\n  ! gethostbyname failed\n\n");
		goto exit;
	}

	if ((server_fd = socket (AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0)
	{
		printf ("ERROR: failed\n  ! socket returned %d\n\n", server_fd);
		goto exit;
	}

	memcpy ((void *) &server_addr.sin_addr,
		(void *) server_host->h_addr,
		server_host->h_length);

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons (req->port);

	if ((ret = connect ( server_fd, (struct sockaddr *) &server_addr,
					sizeof( server_addr ))) < 0)
	{
		printf ("ERROR: failed\n  ! connect returned %d\n\n", ret);
		goto exit_connect;
	}

	if (DEBUG)
		printf (" OK\n");

	if (DEBUG)
		printf ("Write to server:\n");
	fflush (stdout);

	len = make_http_req (req, &reqbuf);

	if (DEBUG)
		printf ("%s\n", reqbuf);

	while ((ret = write (server_fd, reqbuf, len)) <= 0) {
		if (ret != 0) {
			printf ("failed\n  ! write returned %d\n\n", ret);
			goto exit_write;
		}
	}

	struct http_roundtripper rt;
	http_init(&rt, _http_response_funcs, &parser);

	fflush (stdout);
	memset (resbuf, 0, sizeof (resbuf));

	int needmore = 1;
	while (needmore) {
		unsigned char* data = resbuf;
		len = sizeof (resbuf) - 1;
		ret = read(server_fd, resbuf, len);

		if (ret <= 0) {
			printf ("\n---FINISHED or FAILED: ssl_read returned %d\n\n", ret);
			break;
		}

		len = ret;

		while (needmore && ret) {
			int read;
			needmore = http_data (&rt, resbuf, ret, &read);
			ret -= read;
			data += read;
		}
	}
	if (http_iserror(&rt)) {
		fprintf(stderr, "Error parsing data\n");
		goto exit;
	}

exit:
	http_free(&rt);
exit_write:
	free (reqbuf);
exit_connect:
	close (server_fd);

	// XXX:  fill response struct

	return parser.out;
}

static int
strcmp_0 (const char *s1, const char *s2)
{
	if (s1 == s2)
		return 0;
	if (s1 == NULL)
		return -1;
	if (s2 == NULL)
		return 1;
	return strcmp (s1, s2);
}

const char*
thttp_status_to_string (t_thttp_status status)
{
	switch (status) {
	case THTTP_STATUS_CONTINUE:
		return "CONTINUE";
	case THTTP_STATUS_SWITCHING_PROTOCOLS:
		return "SWITCHING_PROTOCOLS";
	case THTTP_STATUS_PROCESSING:
		return "PROCESSING";
	case THTTP_STATUS_OK:
		return "OK";
	case THTTP_STATUS_CREATED:
		return "CREATED";
	case THTTP_STATUS_ACCEPTED:
		 return "ACCEPTED";
	case THTTP_STATUS_NON_AUTHORITATIVE_INFORMATION:
		 return "NON_AUTHORITATIVE_INFORMATION";
	case THTTP_STATUS_NO_CONTENT:
		 return "NO_CONTENT";
	case THTTP_STATUS_RESET_CONTENT:
		 return "RESET_CONTENT";
	case THTTP_STATUS_PARTIAL_CONTENT:
		 return "PARTIAL_CONTENT";
	case THTTP_STATUS_MULTI_STATUS:
		 return "MULTI_STATUS";
	case THTTP_STATUS_MULTIPLE_CHOICES:
		 return "MULTIPLE_CHOICES";
	case THTTP_STATUS_MOVED_PERMANENTLY:
		 return "MOVED_PERMANENTLY";
	case THTTP_STATUS_FOUND:
		 return "FOUND";
	case THTTP_STATUS_SEE_OTHER:
		 return "SEE_OTHER";
	case THTTP_STATUS_NOT_MODIFIED:
		 return "NOT_MODIFIED";
	case THTTP_STATUS_USE_PROXY:
		 return "USE_PROXY";
	case THTTP_STATUS_SWITCH_PROXY:
		 return "SWITCH_PROXY";
	case THTTP_STATUS_TEMPORARY_REDIRECT:
		 return "TEMPORARY_REDIRECT";
	case THTTP_STATUS_BAD_REQUEST:
		 return "BAD_REQUEST";
	case THTTP_STATUS_UNAUTHORIZED:
		 return "UNAUTHORIZED";
	case THTTP_STATUS_PAYMENT_REQUIRED:
		 return "PAYMENT_REQUIRED";
	case THTTP_STATUS_FORBIDDEN:
		 return "FORBIDDEN";
	case THTTP_STATUS_NOT_FOUND:
		 return "NOT_FOUND";
	case THTTP_STATUS_METHOD_NOT_ALLOWED:
		 return "METHOD_NOT_ALLOWED";
	case THTTP_STATUS_NOT_ACCEPTABLE:
		 return "NOT_ACCEPTABLE";
	case THTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED:
		 return "PROXY_AUTHENTICATION_REQUIRED";
	case THTTP_STATUS_REQUEST_TIMEOUT:
		 return "REQUEST_TIMEOUT";
	case THTTP_STATUS_CONFLICT:
		 return "CONFLICT";
	case THTTP_STATUS_GONE:
		 return "GONE";
	case THTTP_STATUS_LENGTH_REQUIRED:
		 return "LENGTH_REQUIRED";
	case THTTP_STATUS_PRECONDITION_FAILED:
		 return "PRECONDITION_FAILED";
	case THTTP_STATUS_REQUEST_ENTITY_TOO_LARGE:
		 return "REQUEST_ENTITY_TOO_LARGE";
	case THTTP_STATUS_REQUEST_URI_TOO_LONG:
		 return "REQUEST_URI_TOO_LONG";
	case THTTP_STATUS_UNSUPPORTED_MEDIA_TYPE:
		 return "UNSUPPORTED_MEDIA_TYPE";
	case THTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE:
		 return "REQUESTED_RANGE_NOT_SATISFIABLE";
	case THTTP_STATUS_EXPECTATION_FAILED:
		 return "EXPECTATION_FAILED";
	case THTTP_STATUS_UNPROCESSABLE_ENTITY:
		 return "UNPROCESSABLE_ENTITY";
	case THTTP_STATUS_LOCKED:
		 return "LOCKED";
	case THTTP_STATUS_FAILED_DEPENDENCY:
		 return "FAILED_DEPENDENCY";
	case THTTP_STATUS_UNORDERED_COLLECTION:
		 return "UNORDERED_COLLECTION";
	case THTTP_STATUS_UPGRADE_REQUIRED:
		 return "UPGRADE_REQUIRED";
	case THTTP_STATUS_NO_RESPONSE:
		 return "NO_RESPONSE";
	case THTTP_STATUS_RETRY_WITH:
		 return "RETRY_WITH";
	case THTTP_STATUS_BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS:
		 return "BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS";
	case THTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS:
		 return "UNAVAILABLE_FOR_LEGAL_REASONS";
	case THTTP_STATUS_INTERNAL_SERVER_ERROR:
		 return "INTERNAL_SERVER_ERROR";
	case THTTP_STATUS_NOT_IMPLEMENTED:
		 return "NOT_IMPLEMENTED";
	case THTTP_STATUS_BAD_GATEWAY:
		 return "BAD_GATEWAY";
	case THTTP_STATUS_SERVICE_UNAVAILABLE:
		 return "SERVICE_UNAVAILABLE";
	case THTTP_STATUS_GATEWAY_TIMEOUT:
		 return "GATEWAY_TIMEOUT";
	case THTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED:
		 return "HTTP_VERSION_NOT_SUPPORTED";
	case THTTP_STATUS_VARIANT_ALSO_NEGOTIATES:
		 return "VARIANT_ALSO_NEGOTIATES";
	case THTTP_STATUS_INSUFFICIENT_STORAGE:
		 return "INSUFFICIENT_STORAGE";
	case THTTP_STATUS_BANDWIDTH_LIMIT_EXCEEDED:
		 return "BANDWIDTH_LIMIT_EXCEEDED";
	case THTTP_STATUS_NOT_EXTENDED:
		return "NOT_EXTENDED";
	}
	return "UNKNOWN";
}

// null terminated string expected. dont blame us for crashes otherwise :)
t_thttp_status
thttp_string_to_status (char* string)
{
	if (!strcmp_0 ("CONTINUE", string)) return THTTP_STATUS_CONTINUE;
	if (!strcmp_0 ("SWITCHING_PROTOCOLS", string)) return THTTP_STATUS_SWITCHING_PROTOCOLS;
	if (!strcmp_0 ("PROCESSING", string)) return THTTP_STATUS_PROCESSING;
	if (!strcmp_0 ("OK", string)) return THTTP_STATUS_OK;
	if (!strcmp_0 ("CREATED", string)) return THTTP_STATUS_CREATED;
	if (!strcmp_0 ("ACCEPTED", string)) return THTTP_STATUS_ACCEPTED;
	if (!strcmp_0 ("NON_AUTHORITATIVE_INFORMATION", string)) return THTTP_STATUS_NON_AUTHORITATIVE_INFORMATION;
	if (!strcmp_0 ("NO_CONTENT", string)) return THTTP_STATUS_NO_CONTENT;
	if (!strcmp_0 ("RESET_CONTENT", string)) return THTTP_STATUS_RESET_CONTENT;
	if (!strcmp_0 ("PARTIAL_CONTENT", string)) return THTTP_STATUS_PARTIAL_CONTENT;
	if (!strcmp_0 ("MULTI_STATUS", string)) return THTTP_STATUS_MULTI_STATUS;
	if (!strcmp_0 ("MULTIPLE_CHOICES", string)) return THTTP_STATUS_MULTIPLE_CHOICES;
	if (!strcmp_0 ("MOVED_PERMANENTLY", string)) return THTTP_STATUS_MOVED_PERMANENTLY;
	if (!strcmp_0 ("FOUND", string)) return THTTP_STATUS_FOUND;
	if (!strcmp_0 ("SEE_OTHER", string)) return THTTP_STATUS_SEE_OTHER;
	if (!strcmp_0 ("NOT_MODIFIED", string)) return THTTP_STATUS_NOT_MODIFIED;
	if (!strcmp_0 ("USE_PROXY", string)) return THTTP_STATUS_USE_PROXY;
	if (!strcmp_0 ("SWITCH_PROXY", string)) return THTTP_STATUS_SWITCH_PROXY;
	if (!strcmp_0 ("TEMPORARY_REDIRECT", string)) return THTTP_STATUS_TEMPORARY_REDIRECT;
	if (!strcmp_0 ("BAD_REQUEST", string)) return THTTP_STATUS_BAD_REQUEST;
	if (!strcmp_0 ("UNAUTHORIZED", string)) return THTTP_STATUS_UNAUTHORIZED;
	if (!strcmp_0 ("PAYMENT_REQUIRED", string)) return THTTP_STATUS_PAYMENT_REQUIRED;
	if (!strcmp_0 ("FORBIDDEN", string)) return THTTP_STATUS_FORBIDDEN;
	if (!strcmp_0 ("NOT_FOUND", string)) return THTTP_STATUS_NOT_FOUND;
	if (!strcmp_0 ("METHOD_NOT_ALLOWED", string)) return THTTP_STATUS_METHOD_NOT_ALLOWED;
	if (!strcmp_0 ("NOT_ACCEPTABLE", string)) return THTTP_STATUS_NOT_ACCEPTABLE;
	if (!strcmp_0 ("METHOD_NOT_ACCEPTABLE", string)) return THTTP_STATUS_METHOD_NOT_ACCEPTABLE;
	if (!strcmp_0 ("PROXY_AUTHENTICATION_REQUIRED", string)) return THTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED;
	if (!strcmp_0 ("REQUEST_TIMEOUT", string)) return THTTP_STATUS_REQUEST_TIMEOUT;
	if (!strcmp_0 ("CONFLICT", string)) return THTTP_STATUS_CONFLICT;
	if (!strcmp_0 ("GONE", string)) return THTTP_STATUS_GONE;
	if (!strcmp_0 ("LENGTH_REQUIRED", string)) return THTTP_STATUS_LENGTH_REQUIRED;
	if (!strcmp_0 ("PRECONDITION_FAILED", string)) return THTTP_STATUS_PRECONDITION_FAILED;
	if (!strcmp_0 ("REQUEST_ENTITY_TOO_LARGE", string)) return THTTP_STATUS_REQUEST_ENTITY_TOO_LARGE;
	if (!strcmp_0 ("REQUEST_URI_TOO_LONG", string)) return THTTP_STATUS_REQUEST_URI_TOO_LONG;
	if (!strcmp_0 ("UNSUPPORTED_MEDIA_TYPE", string)) return THTTP_STATUS_UNSUPPORTED_MEDIA_TYPE;
	if (!strcmp_0 ("REQUESTED_RANGE_NOT_SATISFIABLE", string)) return THTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE;
	if (!strcmp_0 ("EXPECTATION_FAILED", string)) return THTTP_STATUS_EXPECTATION_FAILED;
	if (!strcmp_0 ("UNPROCESSABLE_ENTITY", string)) return THTTP_STATUS_UNPROCESSABLE_ENTITY;
	if (!strcmp_0 ("LOCKED", string)) return THTTP_STATUS_LOCKED;
	if (!strcmp_0 ("FAILED_DEPENDENCY", string)) return THTTP_STATUS_FAILED_DEPENDENCY;
	if (!strcmp_0 ("UNORDERED_COLLECTION", string)) return THTTP_STATUS_UNORDERED_COLLECTION;
	if (!strcmp_0 ("UPGRADE_REQUIRED", string)) return THTTP_STATUS_UPGRADE_REQUIRED;
	if (!strcmp_0 ("NO_RESPONSE", string)) return THTTP_STATUS_NO_RESPONSE;
	if (!strcmp_0 ("RETRY_WITH", string)) return THTTP_STATUS_RETRY_WITH;
	if (!strcmp_0 ("BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS", string)) return THTTP_STATUS_BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS;
	if (!strcmp_0 ("UNAVAILABLE_FOR_LEGAL_REASONS", string)) return THTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS;
	if (!strcmp_0 ("INTERNAL_SERVER_ERROR", string)) return THTTP_STATUS_INTERNAL_SERVER_ERROR;
	if (!strcmp_0 ("NOT_IMPLEMENTED", string)) return THTTP_STATUS_NOT_IMPLEMENTED;
	if (!strcmp_0 ("BAD_GATEWAY", string)) return THTTP_STATUS_BAD_GATEWAY;
	if (!strcmp_0 ("SERVICE_UNAVAILABLE", string)) return THTTP_STATUS_SERVICE_UNAVAILABLE;
	if (!strcmp_0 ("GATEWAY_TIMEOUT", string)) return THTTP_STATUS_GATEWAY_TIMEOUT;
	if (!strcmp_0 ("HTTP_VERSION_NOT_SUPPORTED", string)) return THTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED;
	if (!strcmp_0 ("VARIANT_ALSO_NEGOTIATES", string)) return THTTP_STATUS_VARIANT_ALSO_NEGOTIATES;
	if (!strcmp_0 ("INSUFFICIENT_STORAGE", string)) return THTTP_STATUS_INSUFFICIENT_STORAGE;
	if (!strcmp_0 ("BANDWIDTH_LIMIT_EXCEEDED", string)) return THTTP_STATUS_BANDWIDTH_LIMIT_EXCEEDED;
	if (!strcmp_0 ("NOT_EXTENDED", string)) return THTTP_STATUS_NOT_EXTENDED;
	return THTTP_STATUS_UNKNOWN;
}

t_thttp_proto
thttp_string_to_proto (char *string)
{

	if (!strcmp_0 ("HTTP", string)) return THTTP_PROTO_HTTP;

	return THTTP_PROTO_UNKNOWN;
}

const char*
thttp_proto_to_string (t_thttp_proto proto)
{

	switch(proto) {
	case THTTP_PROTO_HTTP:
		return "HTTP";
	}

	return "UNKNOWN";
}

t_thttp_proto_version
thttp_string_to_proto_version (char *string)
{

	if (!strcmp_0 ("1.0", string))
		return THTTP_PROTO_VERSION_10;
	if (!strcmp_0 ("1.1", string))
		return THTTP_PROTO_VERSION_11;

	return THTTP_PROTO_VERSION_UNKNOWN;
}


const char*
thttp_proto_version_to_string (t_thttp_proto_version proto)
{

	switch(proto) {
	case THTTP_PROTO_VERSION_10:
		return "1.0";
	case THTTP_PROTO_VERSION_11:
		return "1.1";
	}

	return "UNKNOWN";
}

t_thttp_method
thttp_string_to_method (char *string)
{

	if (!strcmp_0 ("GET", string)) return THTTP_METHOD_GET;
	if (!strcmp_0 ("POST", string)) return THTTP_METHOD_POST;
	if (!strcmp_0 ("PUT", string)) return THTTP_METHOD_PUT;
	if (!strcmp_0 ("PATCH", string)) return THTTP_METHOD_PATCH;
	if (!strcmp_0 ("DELETE", string)) return THTTP_METHOD_DELETE;
	if (!strcmp_0 ("HEAD", string)) return THTTP_METHOD_HEAD;
	if (!strcmp_0 ("OPTIONS", string)) return THTTP_METHOD_OPTIONS;

	return THTTP_METHOD_UNKNOWN;
}


const char*
thttp_method_to_string (t_thttp_proto proto)
{

	switch(proto) {
	case THTTP_METHOD_GET:
		return "GET";
	case THTTP_METHOD_POST:
		return "POST";
	case THTTP_METHOD_PUT:
		return "PUT";
	case THTTP_METHOD_PATCH:
		return "PATCH";
	case THTTP_METHOD_DELETE:
		return "DELETE";
	case THTTP_METHOD_HEAD:
		return "HEAD";
	case THTTP_METHOD_OPTIONS:
		return "OPTIONS";
	}

	return "UNKNOWN";
}
