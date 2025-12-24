/*
 * Copyright (c) 2017-2021 Pantacor Ltd.
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define mbedtls_fprintf    fprintf
#define mbedtls_printf    printf
#endif

#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509_crt.h"


#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>

#include "thttp.h"
#include "tinyhttp/http.h"

#define BUF_BLOCKSIZE 8192
#define ENV_CACHAIN "THTTP_CAFILE" // XXX: this has to go away; example should put the file in request

struct http_response_parser {
	thttp_response_t *out;

	size_t headers_at;
	size_t headers_bufsize;
	size_t body_at;
	size_t body_bufsize;

	int filedownload;
	int fd;

	int file_error;
	int file_errno;
	void (*dl_progress_cb)(ssize_t written, ssize_t chunksize, void *priv);
	void *dl_progress_cb_priv;
};

static void (*external_printf)(int level, const char *fmt, va_list args) = NULL;

void thttp_log(thttp_log_level_t level, const char *fmt, ...)
{
	if (!external_printf)
		return;

	va_list args;
	va_start(args, fmt);

	external_printf(level, fmt, args);

	va_end(args);
}

void thttp_set_log_func(void (*func)(int level, const char *fmt, va_list args))
{
	if (func)
		external_printf = func;
}

static char*
buf_nappend (char *buf, size_t *at, const char* append, size_t *bufsize, size_t n)
{
	while (*at + n >= *bufsize) {
		*bufsize += sizeof(char) * BUF_BLOCKSIZE;
		buf = realloc (buf, *bufsize);
	}
	strncpy ((char*)(buf + *at), append, n);
	*at+=n;
	buf[*at]=0;
	return buf;
}

static char*
buf_append (char *buf, size_t *at, const char* append, size_t *bufsize)
{
	buf = buf_nappend(buf, at, append, bufsize, strlen(append));
	return buf;
}

static char*
buf_append_intmax(char *buf, size_t *at, intmax_t append, size_t *bufsize)
{
	char append_buf[256];
	sprintf(append_buf, "%jd", append);
	buf = buf_append (buf, at, append_buf, bufsize);
	return buf;
}

static char*
buf_append_int(char *buf, size_t *at, int append, size_t *bufsize)
{
	return buf_append_intmax(buf, at, (intmax_t)append, bufsize);
}


static size_t
make_http_req (thttp_request_t *req, char **buf)
{
	size_t bufsize = BUF_BLOCKSIZE * sizeof(char);
	size_t at = 0;

	// allocate at first and set first char to 0
	*buf = malloc (bufsize);
	if (!*buf)
		return 0;
	**buf = 0;

	// append METHOD /PATH/ HTTP/VERSION line
	*buf = buf_append (*buf, &at, thttp_method_to_string (req->method), &bufsize);
	*buf = buf_append (*buf, &at, " ", &bufsize);
	if (req->baseurl) {
		*buf = buf_append (*buf, &at, req->baseurl, &bufsize);
	}
	*buf = buf_append (*buf, &at, req->path, &bufsize);
	*buf = buf_append (*buf, &at, " ", &bufsize);
	*buf = buf_append (*buf, &at, thttp_proto_to_string (req->proto), &bufsize);
	*buf = buf_append (*buf, &at, "/", &bufsize);
	*buf = buf_append (*buf, &at, thttp_proto_version_to_string (req->proto_version), &bufsize);
	*buf = buf_append (*buf, &at, "\r\n", &bufsize);

	// Host: hostname:port header line goes first (even for HTTP/1.0)
	*buf = buf_append (*buf, &at, "Host: ", &bufsize);
	*buf = buf_append (*buf, &at, req->host, &bufsize);
	*buf = buf_append (*buf, &at, ":", &bufsize);
	*buf = buf_append_int (*buf, &at, req->port, &bufsize);
	*buf = buf_append (*buf, &at, "\r\n", &bufsize);

	// Connection: close - always to prevent TIMEWAIT sockets
	*buf = buf_append (*buf, &at, "Connection: close\r\n", &bufsize);

	// User-Agent: user agent if provided
	if (req->user_agent) {
		*buf = buf_append (*buf, &at, "User-Agent: ", &bufsize);
		*buf = buf_append (*buf, &at, req->user_agent, &bufsize);
		*buf = buf_append (*buf, &at, "\r\n", &bufsize);
	}

	// append headers; one each line!
	for (int i = 0; i < req->nr_headers; i++) {
		*buf = buf_append (*buf, &at, req->headers[i], &bufsize);
		*buf = buf_append (*buf, &at, "\r\n", &bufsize);
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
	} else if (req->fd >= 0) {
		*buf = buf_append (*buf, &at, "Content-Length: ", &bufsize);
		*buf = buf_append_intmax (*buf, &at, req->len, &bufsize);
		*buf = buf_append (*buf, &at, "\r\n", &bufsize);
		*buf = buf_append (*buf, &at, "Content-Type: ", &bufsize);
		*buf = buf_append (*buf, &at, req->body_content_type, &bufsize);
		*buf = buf_append (*buf, &at, "\r\n", &bufsize);
		*buf = buf_append (*buf, &at, "\r\n", &bufsize);
	} else {
		*buf = buf_append (*buf, &at, "\r\n", &bufsize);
	}

	return at;
}

static void*
_response_realloc(void* opaque, void* ptr, int size)
{
	if (size <= 0) {
		free(ptr);
		return NULL;
	}

	return realloc(ptr, size);
}

static void
_response_body(void* opaque, const char* data, int size)
{
	struct http_response_parser* parser = (struct http_response_parser*) opaque;

	if (parser->filedownload) {
		int r;
		r = write (parser->fd, data, size);
		if (r < size) {
			thttp_log(LOG_WARN, "write: %s", strerror(errno));
			parser->file_error = 1;
			parser->file_error = errno;
		}
		if (parser->dl_progress_cb) {
			parser->dl_progress_cb(r, size, parser->dl_progress_cb_priv);
		}
	} else {
		parser->out->body = buf_nappend (parser->out->body, &parser->body_at, data, &parser->body_bufsize, size);
	}
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

thttp_request_t* thttp_request_new_0(void);
thttp_request_tls_t* thttp_request_tls_new_0(void);

thttp_request_t*
thttp_request_new_0()
{
	thttp_request_t *self = calloc (1, sizeof(thttp_request_tls_t));
	if (self) {
		self->fd = -1;
		self->is_tls=0;
	}

	return (thttp_request_t*) self;
}

thttp_request_tls_t*
thttp_request_tls_new_0()
{
	thttp_request_t *self = thttp_request_new_0();
	if (self)
		self->is_tls=1;
	return (thttp_request_tls_t*) self;
}

void
thttp_request_free (thttp_request_t* ptr)
{
	if (ptr->baseurl)
		free(ptr->baseurl);
	for (int i = 0; i < ptr->nr_headers; i++) {
		if (ptr->headers[i])
			free(ptr->headers[i]);
	}
	if (ptr->headers)
		free(ptr->headers);
	free (ptr);
}

void thttp_add_headers(struct thttp_request *req, char **headers, int nr_headers)
{
	int new_nr_headers;
	if (!nr_headers)
		return;

	new_nr_headers = req->nr_headers + nr_headers;
	req->headers = realloc(req->headers, new_nr_headers * sizeof(char*));
	for (int i = req->nr_headers; i < new_nr_headers; i++) {
		req->headers[req->nr_headers] = strdup(headers[i]);
		req->nr_headers++;
	}

	thttp_log(LOG_DEBUG, "added %d headers to request that now has %d headers in total",
		nr_headers,
		req->nr_headers);
}

void
thttp_response_free (thttp_response_t* ptr)
{
	char **headers_i = ptr->headers;

	while (headers_i && *headers_i) {
		free(*headers_i);
		headers_i++;
	}
	if (ptr->headers)
		free(ptr->headers);
	if(ptr->body)
		free(ptr->body);
	free (ptr);
}

struct _req_ctx_plain {
	int server_fd;
	struct sockaddr_in server_addr;
	struct hostent *server_host;
};

struct _req_ctx_tls {
	mbedtls_net_context server_fd;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;
};

static int is_remote_reachable(int sockfd, struct sockaddr *rp, socklen_t len)
{
	struct timeval tv;
	fd_set fdset;
	int orig_flags = fcntl(sockfd, F_GETFL, NULL);
	int ret = 0;
	char addr[INET_ADDRSTRLEN] = {0};
	char addr6[INET6_ADDRSTRLEN] = {0};

	fcntl(sockfd, F_SETFL, orig_flags | O_NONBLOCK);

	if (DEBUG) {
		if (rp->sa_family == AF_INET) {

			if (inet_ntop(AF_INET,
				&((struct sockaddr_in*)rp)->sin_addr, addr, sizeof(addr))) {
				mbedtls_printf( "attempting connection to %s:%d\n",
						addr, htons(((struct sockaddr_in*)rp)->sin_port));
			}
		}
		else if (rp->sa_family == AF_INET6) {
			if (inet_ntop(AF_INET6,
				&((struct sockaddr_in6*)rp)->sin6_addr,addr6, sizeof(addr6))) {
				mbedtls_printf( "attempting connection to %s:%d\n",
						addr6, htons(((struct sockaddr_in6*)rp)->sin6_port));
			}

		}
	}

	ret = connect(sockfd, rp, len);

	if (!ret) {
		thttp_log(LOG_WARN, "connect: %s", strerror(errno));
		ret = 1;
		goto out;
	}

	if (errno != EINPROGRESS) {
		ret = 0;
		goto out;
	}

	tv.tv_sec = 2;
	tv.tv_usec = 0;

	FD_ZERO(&fdset);
	FD_SET(sockfd, &fdset);

	ret = select(sockfd + 1, 0, &fdset, 0, &tv);
	if (ret < 0) {
		if (errno != EINTR)
			thttp_log(LOG_WARN, "select: %s", strerror(errno));
		// if we get an EINTR here, that means we probably
		// got a hangup -> in all cases: not reachable...
		goto out;
	} else if (ret == 0) {
		goto out;
	}

	len = sizeof(ret);
	if(getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &ret, &len))
		thttp_log(LOG_WARN, "getsockopt: %s", strerror(errno));
	ret = !ret ? 1 : 0;
out:
	fcntl(sockfd, F_SETFL, orig_flags);
	return ret;

}


static int
_sock_connect (char *host, char *port, struct sockaddr *sock)
{
	int fd = -1, ret = 0;
	struct addrinfo hints, *result = 0, *rp;

	// ignore SIGPIPE signal to disable the default behavior (end the process).
	// that way, we can handle send/write errors in our code
	signal(SIGPIPE, SIG_IGN);

	/*
	 * If conn, try resolved PH IP first.
	 * */

	if (sock->sa_family) {
		fd = socket(sock->sa_family, SOCK_STREAM, IPPROTO_IP);
		if (fd >= 0) {
			if (is_remote_reachable(fd, sock, sizeof(*sock)))
				goto ret;

			close(fd);
			fd = -1;
		} else
			thttp_log(LOG_WARN, "socket: %s", strerror(errno));
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family |= AF_UNSPEC;

	ret = getaddrinfo(host, port, &hints, &result);
	if (ret) {
		thttp_log(LOG_WARN, "getaddrinfo: %s (%s)", strerror(errno), gai_strerror(ret));
		return -1;
	}

	rp = result;
	while (rp) {
		fd = socket(rp->ai_family, SOCK_STREAM, IPPROTO_IP);

		if (fd < 0) {
			thttp_log(LOG_WARN, "socket: %s", strerror(errno));
			goto out;
		}

		if (is_remote_reachable(fd, rp->ai_addr, rp->ai_addrlen)) {
			*sock = *rp->ai_addr;
			break;
		}

		close(fd);
		fd = -1; /*Reset socket desc*/
		rp = rp->ai_next;
	}
out:
	if (fd >= 0) {
		int flags = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags)))
			thttp_log(LOG_WARN, "setsockopt: %s", strerror(errno));
		flags = 300;
		if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &flags, sizeof(flags)))
			thttp_log(LOG_WARN, "setsockopt: %s", strerror(errno));
	}

	if (result)
		freeaddrinfo(result);

ret:
	return fd;
}


static int
thttp_request_connect_plain (thttp_request_t* req,
			     struct _req_ctx_plain *ctx)
{
	char portc[16];
	// if proxy we connect to proxy
	if (req->host_proxy && strlen(req->host_proxy) > 0) {
		if (DEBUG)
			mbedtls_printf("connecting through proxy: %s/%d\n", req->host_proxy, req->port_proxy);
		snprintf(portc, sizeof(portc), "%d", req->port_proxy);
		ctx->server_fd = _sock_connect(req->host_proxy, portc, &req->conn);
	} else {
		if (DEBUG)
			mbedtls_printf("connecting directly to host/port: %s/%d\n", req->host, req->port);
		snprintf(portc, sizeof(portc), "%d", req->port);
		ctx->server_fd = _sock_connect(req->host, portc, &req->conn);
	}
	if (DEBUG)
		mbedtls_printf (" OK serverfd %d\n", ctx->server_fd);

	return ctx->server_fd >= 0 ? 0 : -1;

}

static void my_debug (void *ctx, int level,
		      const char *file, int line,
		      const char *str)
{
	((void) level);

	mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
	fflush((FILE *) ctx);
}


static int
do_ctx_connect_tls (int fd,
		    thttp_request_t *req,
		    struct _req_ctx_tls *ctx)
{
	const char *pers = "thttp_client";
	int ret = 0;
	uint32_t flags;
	thttp_request_tls_t *tls_req = (thttp_request_tls_t*) req;
	time_t start;
	const time_t MAX_SECS_FOR_HANDSHAKE = 30;
#if defined(MBEDTLS_DEBUG_C)
	mbedtls_debug_set_threshold(0);
#endif

	/*
	 * 0. Initialize the RNG and the session data
	 */
	mbedtls_net_init(&ctx->server_fd);
	mbedtls_ssl_init(&ctx->ssl);
	mbedtls_ssl_config_init(&ctx->conf);
	mbedtls_x509_crt_init(&ctx->cacert);
	mbedtls_ctr_drbg_init(&ctx->ctr_drbg);

	if (VERBOSE) {
		mbedtls_printf("\n  . Seeding the random number generator...");
		fflush(stdout);
	}

	mbedtls_entropy_init(&ctx->entropy);
	if( ( ret = mbedtls_ctr_drbg_seed( &ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy,
					   (const unsigned char *) pers,
					   strlen( pers ) ) ) != 0 )
	{
		mbedtls_printf(" failed seeding random generator\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
		goto exit;
	}

	if (DEBUG)
		mbedtls_printf(" ok\n");

	/*
	 * 0. Initialize certificates
	 */
	if (tls_req->crtfiles) {
		char **buf = tls_req->crtfiles;
		while (*buf) {
			if  (DEBUG) {
				mbedtls_printf("  . Loading the CA root certificate from file: %s ...",
					       *buf);
				fflush(stdout);
			}

			ret = mbedtls_x509_crt_parse_file(&ctx->cacert, *buf);
			if( ret < 0 )
			{
				mbedtls_printf( " failed loading CA root from %s\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n",
						*buf, -ret );
				goto exit;
			}
			if (DEBUG)
				mbedtls_printf(" ok\n");
			buf++;
		}
	} else if (getenv(ENV_CACHAIN)) {
		if (DEBUG) {
			mbedtls_printf("  . Loading the CA root certificate from file: %s ...",
				       getenv(ENV_CACHAIN));
			fflush(stdout);
		}

		ret = mbedtls_x509_crt_parse_file(&ctx->cacert, getenv(ENV_CACHAIN));
		if( ret < 0 )
		{
			mbedtls_printf( " failed to load cert %s\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n",
					getenv(ENV_CACHAIN), -ret );
			goto exit;
		}
		if (DEBUG)
			mbedtls_printf(" ok\n");
	} else {
		mbedtls_printf( "ERROR: we do not have built-in certificates for libthttp");
		ret = -1;
		goto exit;
	}


	/*
	 * 1. Start the connection
	 */
	if (DEBUG) {
		mbedtls_printf( "  . Connecting to tcp/%s/%d...", req->host, req->port );
		fflush( stdout );
	}


	ctx->server_fd.fd = fd;

	mbedtls_net_set_nonblock(&ctx->server_fd);

	if (DEBUG)
		mbedtls_printf( " ok\n" );

	if (DEBUG) {
		mbedtls_printf( "  . Setting up the SSL/TLS structure..." );
		fflush( stdout );
	}

	if( ( ret = mbedtls_ssl_config_defaults( &ctx->conf,
						 MBEDTLS_SSL_IS_CLIENT,
						 MBEDTLS_SSL_TRANSPORT_STREAM,
						 MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
	{
		mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
		goto exit;
	}

	if (DEBUG)
		mbedtls_printf( " ok\n" );

	/* XXX: FIXME
	 * OPTIONAL is not optimal for security,
	 * but makes interop easier in this simplified example
	 */
#ifdef THTTP_DEVELOPMENT
	mbedtls_ssl_conf_authmode( &ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
#else
	mbedtls_ssl_conf_authmode( &ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED );
#endif
	mbedtls_ssl_conf_ca_chain( &ctx->conf, &ctx->cacert, NULL );
	mbedtls_ssl_conf_rng( &ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg );
	mbedtls_ssl_conf_dbg( &ctx->conf, my_debug, stdout );

	if ((ret = mbedtls_ssl_setup( &ctx->ssl, &ctx->conf)) != 0)
	{
		mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
		goto exit;
	}

	if ((ret = mbedtls_ssl_set_hostname( &ctx->ssl, req->host )) != 0)
	{
		mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
		goto exit;
	}

	mbedtls_ssl_set_bio (&ctx->ssl, &ctx->server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

	/*
	 * 4. Handshake
	 */
	if (DEBUG) {
		mbedtls_printf( "  . Performing the SSL/TLS handshake..." );
		fflush( stdout );
	}
	start = time(NULL);

	/* start writing */
	ret = MBEDTLS_ERR_SSL_WANT_WRITE;
	do {
		/*
		 * TODO: Make 2000 (ms timeout) to a define.
		 * */

		if ( start + MAX_SECS_FOR_HANDSHAKE < time(NULL)){
			break;
		}

		if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			ret = mbedtls_net_poll(&ctx->server_fd,
					       MBEDTLS_NET_POLL_WRITE, 500);
			// we have a timeout ... lets remember what we wanted to do and continue
			if (!ret) {
				ret = MBEDTLS_ERR_SSL_WANT_WRITE;
				continue;
			}
		}
		else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
			ret = mbedtls_net_poll(&ctx->server_fd,
					MBEDTLS_NET_POLL_READ, 500);
			if (!ret) {
				ret = MBEDTLS_ERR_SSL_WANT_READ;
				continue;
			}
		}

		if (!ret) {
			mbedtls_printf("This code must not happen");
			goto exit;
		}

		if ( !(ret & MBEDTLS_NET_POLL_WRITE) &&  !(ret & MBEDTLS_NET_POLL_READ))
			goto exit;

		ret = mbedtls_ssl_handshake(&ctx->ssl);

	}while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	if (ret) {
		mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
		goto exit;
	}

	if (DEBUG)
		mbedtls_printf( " ok\n" );

	/*
	 * 5. Verify the server certificate
	 */
	if (DEBUG)
		mbedtls_printf( "  . Verifying peer X.509 certificate..." );

	/* In real life, we probably want to bail out when ret != 0 */
	if((flags = mbedtls_ssl_get_verify_result(&ctx->ssl))!= 0 ) {
		char vrfy_buf[512];
		mbedtls_printf( " failed\n" );
		mbedtls_x509_crt_verify_info(vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags);
		mbedtls_printf("%s\n", vrfy_buf);
	} else {
		if (DEBUG)
			mbedtls_printf( " ok\n" );
	}
	return ret;
exit:
	close(fd);
	return ret;
}


static int
do_ctx_plain_write(thttp_request_t* req,
		   struct _req_ctx_plain *ctx_plain,
		   char *buf,
		   int len)
{
	int ret = write (ctx_plain->server_fd, buf, len);
	if (ret < 0)
		thttp_log(LOG_WARN, "write: %s", strerror(errno));
	return ret;
}

static int
do_ctx_tls_write(thttp_request_t* req,
		 struct _req_ctx_tls *ctx,
		 char *buf,
		 int len)
{
	int at = 0, size = 0;
	int ret;
	int has_error = 0;

	while( (len) > 0 ) {
		size = len > BUF_BLOCKSIZE ? BUF_BLOCKSIZE : len;
		int written = 0;
		// we start with write (for obvious reasons)
		int pollmask = MBEDTLS_NET_POLL_WRITE;
		while (size > 0) {
			/*
			 * TODO: Make 2000 (ms timeout) to a define.
			 * */
			if ( mbedtls_net_poll(&ctx->server_fd, pollmask, 2000)
					!= pollmask) {
				has_error = -1;
				break;
			}
			ret = mbedtls_ssl_write( &ctx->ssl, (unsigned char*)(buf+at), size);
			if (!ret)
				break;

			if(ret < 0) {
				if (ret != MBEDTLS_ERR_SSL_WANT_WRITE &&
						ret != MBEDTLS_ERR_SSL_WANT_READ &&
						ret != MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS &&
						ret != MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
					has_error = ret;
					break;
				}
				else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
					pollmask = MBEDTLS_NET_POLL_WRITE;
					continue;
				}
				else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
					pollmask = MBEDTLS_NET_POLL_READ;
					continue;
				}
				else {
					// for IN_PROGRESS ones we assume we need to write now...
					pollmask = MBEDTLS_NET_POLL_WRITE;
					continue;
				}
			}
			at += ret;
			written += ret;
			size -= ret;
		}
		len -= written;
		if (!written || has_error)  /*Unable to write anything*/
			break;
	}

	return has_error ? has_error : at;
}

static int
do_ctx_write(thttp_request_t* req,
	     struct _req_ctx_plain *ctx_plain,
	     struct _req_ctx_tls *ctx_tls,
	     char *buf,
	     int len)
{
	if (req->is_tls)
	{
		return do_ctx_tls_write(req, ctx_tls, buf, len);
	}

	return do_ctx_plain_write(req, ctx_plain, buf, len);
}

static int
do_ctx_plain_read(thttp_request_t* req,
		  struct _req_ctx_plain *ctx_plain,
		  char *buf,
		  int len)
{
	int ret = read(ctx_plain->server_fd, buf, len);
	if (ret < 0)
		thttp_log(LOG_WARN, "read: %s", strerror(errno));
	return ret;
}
static int
do_ctx_tls_read(thttp_request_t* req,
		struct _req_ctx_tls *ctx,
		char *buf,
		int len)
{
	int ret = -1;
	int to_read = len;

	if(DEBUG) {
		mbedtls_printf( "  < Read from server:" );
		fflush(stdout);
	}

	memset(buf, 0, len);

	int pollmask = MBEDTLS_NET_POLL_READ;
	while (len > 0) {
		if ( mbedtls_net_poll(&ctx->server_fd, pollmask, 2000)
				!= pollmask) {
			if (DEBUG)
				mbedtls_printf("poll returned -ve value..\n");
			break;
		}

		ret = mbedtls_ssl_read(&ctx->ssl, (unsigned char*)buf , len);

		if (ret == 0 )
			break;

		else if (ret > 0) {
			len -= ret;
			buf += ret;
			break;
		}
		else {
			if(ret == MBEDTLS_ERR_SSL_WANT_READ) {
				pollmask = MBEDTLS_NET_POLL_READ;
				continue;
			} else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
				pollmask = MBEDTLS_NET_POLL_WRITE;
				continue; // XXX: make proper enum or something for AGAIN
			}
			else
				break;
		}
	}
	if (DEBUG && VERBOSE)
		mbedtls_printf("%d bytes read\n\n%s", to_read, (char *) buf - (to_read - len));
	else if (DEBUG)
		mbedtls_printf("%d bytes read\n\n", to_read);

	return to_read - len;
}

static int
do_ctx_read(thttp_request_t* req,
	    struct _req_ctx_plain *ctx_plain,
	    struct _req_ctx_tls *ctx_tls,
	    char *buf,
	    int len)
{
	if (req->is_tls) {
		return do_ctx_tls_read(req, ctx_tls, buf, len);
	}

	return do_ctx_plain_read(req, ctx_plain, buf, len);
}

static int
do_ctx_plain_close (thttp_request_t* req,
		    struct _req_ctx_plain *ctx_plain)
{
	return close(ctx_plain->server_fd);
}

static int
do_ctx_tls_close (thttp_request_t* req,
		  struct _req_ctx_tls *ctx)
{
	mbedtls_net_free( &ctx->server_fd );
	mbedtls_x509_crt_free( &ctx->cacert );
	mbedtls_ssl_free( &ctx->ssl );
	mbedtls_ssl_config_free( &ctx->conf );
	mbedtls_ctr_drbg_free( &ctx->ctr_drbg );
	mbedtls_entropy_free( &ctx->entropy );

	return 0;
}

static int
do_ctx_close(thttp_request_t* req,
	    struct _req_ctx_plain *ctx_plain,
	    struct _req_ctx_tls *ctx_tls)
{
	if (req->is_tls) {
		return do_ctx_tls_close(req, ctx_tls);
	}

	return do_ctx_plain_close(req, ctx_plain);
}

static int
do_ctx_connect (thttp_request_t* req,
		struct _req_ctx_plain *ctx_plain,
		struct _req_ctx_tls *ctx_tls)
{

	int ret;
	char resbuf[1024];
	char *httpconnect = 0;

	int upstreamtls = req->baseurl ? !strncmp (req->baseurl, "https:", 6) : strlen(req->path) >= 6 && !strncmp (req->path, "https:", 6);

	if (req->host_proxy && req->proxyconnect && upstreamtls) {
		char *p;
		httpconnect = malloc(sizeof(char) * (strlen("CONNECT %s HTTP/1.1\n\n") + strlen(req->host) + 7));
		sprintf(httpconnect, "CONNECT %s:%d HTTP/1.1\n\n", req->host, req->port);

		ret = thttp_request_connect_plain (req, ctx_plain);

		if (ret < 0) {
			free (httpconnect);
			return ret;
		}

		ret = do_ctx_plain_write(req,
					 ctx_plain,
					 httpconnect,
					 strlen(httpconnect));
		free(httpconnect);

		if (ret < 0) {
			goto exit;
		}

		ret = do_ctx_plain_read(req,
					ctx_plain,
					resbuf,
					1024);
		if (ret < 0) {
			goto exit;
		}

		if (strncmp(resbuf, "HTTP/",5)) {
			mbedtls_printf("error connecting through proxy tunnel '%s'\n",resbuf);
			goto exit;
		}

		p = strchr(resbuf, ' ');

		if (strncmp(p+1, "200", 3)) {
			mbedtls_printf("proxy tunnel did not return 200 error code '%s'\n",resbuf);
			goto exit;
		}

		req->is_tls = 1;
		ret = do_ctx_connect_tls(ctx_plain->server_fd, req, ctx_tls);

		return ret;
	} else if (req->is_tls) {
		ret = thttp_request_connect_plain (req, ctx_plain);
		if (ret < 0)
			goto exit;
		ret = do_ctx_connect_tls(ctx_plain->server_fd, req, ctx_tls);
		return ret;
	}

	return thttp_request_connect_plain (req, ctx_plain);

 exit:
	return -1;
}


static int
thttp_request_do_abstract (thttp_request_t* req, struct http_response_parser *parser)
{
	int ret = -1, len, bytes;
	struct _req_ctx_plain ctx_plain;
	struct _req_ctx_tls ctx_tls;
	char *reqbuf = 0;
	char filebuf[4096];
	char resbuf[4*8192];
	int needmore = 1;

	memset(&ctx_plain, 0, sizeof(ctx_plain));
	memset(&ctx_tls, 0, sizeof(ctx_tls));

	parser->out = calloc(1, sizeof(thttp_response_t));
	if (!parser->out)
		goto exit_connect;

	if (DEBUG) {
		mbedtls_printf("Connecting to tcp/%s/%4d...", req->host,
		       req->port);
		fflush (stdout);
	}

	if((ret = do_ctx_connect(req, &ctx_plain, &ctx_tls)) < 0) {
		goto exit_connect;
	}

	if (DEBUG){
		mbedtls_printf ("Write to server:\n");
		fflush (stdout);
	}

	len = make_http_req(req, &reqbuf);

	if (DEBUG)
		mbedtls_printf ("%s\n", reqbuf);

	thttp_log(LOG_DEBUG, "%s\n", reqbuf);

	while ((ret = do_ctx_write(req, &ctx_plain, &ctx_tls, reqbuf, len)) <= 0) {
		if (ret < 0) {
			mbedtls_printf ("failed\n  ! write returned %d\n\n", ret);
			goto exit_write;
		}
	}

	if (req->fd >= 0) {
		thttp_log(LOG_DEBUG, "about to upload fd %d\n", req->fd);
		while ((bytes = read(req->fd, filebuf, 4096)) > 0) {
			if (bytes < 0)
				thttp_log(LOG_WARN, "read: %s", strerror(errno));
			do {
				ret = do_ctx_write(req, &ctx_plain, &ctx_tls, filebuf, bytes);
				if (ret < 0) {
					thttp_log(LOG_WARN, "do_ctx_write: %s", strerror(errno));
					goto exit_write;
				}
			} while (ret <= 0);
		}
	}

	struct http_roundtripper rt;
	http_init(&rt, _http_response_funcs, parser);
	memset(resbuf, 0, sizeof(resbuf));

	while (needmore) {
		char* data = resbuf;
		len = sizeof(resbuf);
		ret = do_ctx_read(req, &ctx_plain, &ctx_tls, resbuf, len);

		if(ret <= 0) {
			if (DEBUG)
				mbedtls_printf ("\n---FINISHED or FAILED: ssl_read returned %d\n\n", ret);
			break;
		}

		len = ret;

		while(needmore && ret) {
			int read;
			needmore = http_data(&rt, resbuf, ret, &read);
			ret -= read;
			data += read;
			if(parser->file_error) {
				mbedtls_printf("Error writing to file\n");
				goto exit;
			}
		}
	}
	if(http_iserror(&rt)) {
		mbedtls_printf("Error parsing data\n");
		goto exit;
	}

exit:
	http_free(&rt);
	mbedtls_ssl_close_notify(&ctx_tls.ssl);
exit_write:
	free (reqbuf);
exit_connect:
	do_ctx_close(req, &ctx_plain, &ctx_tls);

	return ret < 0 ? ret : 0;
}

thttp_response_t*
thttp_request_do (thttp_request_t *req)
{
	int rv;
	struct http_response_parser parser;
	memset (&parser, 0, sizeof (parser));

	rv = thttp_request_do_abstract (req, &parser);

	if (DEBUG)
		mbedtls_printf("thttp parser return: ret = %d, parser.out=%s\n",
				rv, (parser.out? "nil":parser.out->body));
	return parser.out;
}

thttp_response_t*
thttp_request_do_file_with_cb (thttp_request_t *req, int fd,
		void (*progress_cb)(ssize_t written, ssize_t chunksize, void *priv),
		void *priv)
{
	int rv;
	struct http_response_parser parser;
	memset (&parser, 0, sizeof (parser));
	parser.filedownload = 1;
	parser.fd = fd;
	parser.dl_progress_cb = progress_cb;
	parser.dl_progress_cb_priv = priv;
	rv = thttp_request_do_abstract (req, &parser);
	if (DEBUG)
		mbedtls_printf("thttp parser file done. ret = %d", rv);
	return parser.out;
}

thttp_response_t* thttp_request_do_file (thttp_request_t *req, int fd)
{
	return thttp_request_do_file_with_cb(req, fd, NULL, NULL);
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
thttp_status_to_string (thttp_status_t status)
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
	default:
		return "UNKNOWN";
	}
}

// null terminated string expected. dont blame us for crashes otherwise :)
thttp_status_t
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

thttp_proto_t
thttp_string_to_proto (char *string)
{

	if (!strcmp_0 ("HTTP", string)) return THTTP_PROTO_HTTP;

	return THTTP_PROTO_UNKNOWN;
}

const char*
thttp_proto_to_string (thttp_proto_t proto)
{

	switch(proto) {
	case THTTP_PROTO_HTTP:
		return "HTTP";
	default:
		return "UNKNOWN";
	}

}

thttp_proto_version_t
thttp_string_to_proto_version (char *string)
{

	if (!strcmp_0 ("1.0", string))
		return THTTP_PROTO_VERSION_10;
	if (!strcmp_0 ("1.1", string))
		return THTTP_PROTO_VERSION_11;

	return THTTP_PROTO_VERSION_UNKNOWN;
}


const char*
thttp_proto_version_to_string (thttp_proto_version_t proto)
{

	switch(proto) {
	case THTTP_PROTO_VERSION_10:
		return "1.0";
	case THTTP_PROTO_VERSION_11:
		return "1.1";
	default:
		return "UNKNOWN";
	}

}

thttp_method_t
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
thttp_method_to_string (thttp_method_t method)
{

	switch(method) {
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
	default:
		return "UNKNOWN";
	}
}
