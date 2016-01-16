/*
 * Copyright (c) 2007-2012, Vsevolod Stakhov
 * All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer. Redistributions in binary form
 * must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with
 * the distribution. Neither the name of the author nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.

 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "memcached.h"
#include <netdb.h>

#define CRLF "\r\n"
#define END_TRAILER "END" CRLF
#define STORED_TRAILER "STORED" CRLF
#define NOT_STORED_TRAILER "NOT STORED" CRLF
#define EXISTS_TRAILER "EXISTS" CRLF
#define DELETED_TRAILER "DELETED" CRLF
#define NOT_FOUND_TRAILER "NOT_FOUND" CRLF
#define CLIENT_ERROR_TRAILER "CLIENT_ERROR"
#define SERVER_ERROR_TRAILER "SERVER_ERROR"

#define READ_BUFSIZ 1500
#define MAX_RETRIES 3

/*
 * Poll file descriptor for read or write during specified timeout
 */
static int poll_d(int fd, u_char want_read, u_char want_write, int timeout)
{
	int r;
	struct pollfd fds[1];

	fds->fd = fd;
	fds->revents = 0;
	fds->events = 0;

	if (want_read != 0) {
		fds->events |= POLLIN;
	}
	if (want_write != 0) {
		fds->events |= POLLOUT;
	}
	while ((r = poll (fds, 1, timeout)) < 0) {
		if (errno != EINTR)
			break;
	}

	return r;
}

/*
 * Write to syslog if OPT_DEBUG is specified
 */
static void memc_log(const memcached_ctx_t *ctx, int line, const char *fmt, ...)
{
	va_list args;

	va_start (args, fmt);
	syslog (LOG_DEBUG, "memc_debug(%d): host: %s, port: %d", line, ctx->addr,
			ntohs(ctx->port));
	vsyslog (LOG_DEBUG, fmt, args);
	va_end (args);
}

/*
 * Make socket for tcp connection
 */
static int memc_make_tcp_sock(memcached_ctx_t *ctx)
{
	struct sockaddr_in sc;
	int ofl, r;
	struct addrinfo hints, *res, *res0;
	int error;
	int s;
	const char *cause = NULL;
	char portbuf[32];

	memset(&hints, 0, sizeof(hints));
	snprintf(portbuf, sizeof(portbuf), "%d", (int) ntohs (ctx->port));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;
	error = getaddrinfo (ctx->addr, portbuf, &hints, &res0);

	if (error) {
		memc_log (ctx, __LINE__, "memc_make_tcp_sock: getaddrinfo failed: %s",
				gai_strerror (error));
		return -1;
	}

	s = -1;
	for (res = res0; res; res = res->ai_next) {
		s = socket (res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s < 0) {
			cause = "socket";
			error = errno;
			continue;
		}

		ofl = fcntl (s, F_GETFL, 0);
		fcntl (s, F_SETFL, ofl | O_NONBLOCK);

		if (connect (s, res->ai_addr, res->ai_addrlen) < 0) {
			if (errno == EINPROGRESS || errno == EAGAIN) {
				break;
			}

			cause = "connect";
			error = errno;
			close (s);
			s = -1;
			continue;
		}

		break; /* okay we got one */
	}

	freeaddrinfo (res0);
	ctx->sock = s;

	if (s < 0) {
		memc_log (ctx, __LINE__, "memc_make_tcp_sock: connect failed: %s: %s",
				cause, strerror (error));
		return -1;
	}

	/* Get write readiness */
	if (poll_d (ctx->sock, 0, 1, ctx->timeout) == 1) {
		ctx->opened = 1;
		return 0;
	}
	else {
		memc_log (ctx, __LINE__, "memc_make_tcp_sock: poll() timeout");
		close (ctx->sock);
		ctx->sock = -1;
	}

	return -1;
}

/* 
 * Parse VALUE reply from server and set len argument to value returned by memcached 
 */
static int memc_parse_header(char *buf, size_t *len, char **end)
{
	char *p, *c;
	int i;

	/* VALUE <key> <flags> <bytes> [<cas unique>]\r\n */
	c = strstr (buf, CRLF);
	if (c == NULL) {
		return -1;
	}
	*end = c + sizeof(CRLF) - 1;

	if (strncmp (buf, "VALUE ", sizeof("VALUE ") - 1) == 0) {
		p = buf + sizeof("VALUE ") - 1;

		/* Read bytes value and ignore all other fields, such as flags and key */
		for (i = 0; i < 2; i++) {
			while (p++ < c && *p != ' ')
				;

			if (p > c) {
				return -1;
			}
		}
		*len = strtoul (p, &c, 10);
		return 1;
	}
	/* If value not found memcached return just END\r\n , in this case return 0 */
	else if (strncmp (buf, END_TRAILER, sizeof(END_TRAILER) - 1) == 0) {
		return 0;
	}

	return -1;
}
/*
 * Common read command handler for memcached
 */
memc_error_t memc_read(memcached_ctx_t *ctx, const char *cmd,
		memcached_param_t *params, size_t *nelem)
{
	char read_buf[READ_BUFSIZ];
	char *p;
	unsigned int i, retries;
	ssize_t r, sum = 0, written = 0;
	size_t datalen;
	struct iovec iov[2];

	for (i = 0; i < *nelem; i++) {
		r = snprintf(read_buf, READ_BUFSIZ, "%s %s" CRLF, cmd, params[i].key);
		memc_log (ctx, __LINE__,
				"memc_read: send read request to memcached: %s", read_buf);
		if (write (ctx->sock, read_buf, r) == -1) {
			memc_log (ctx, __LINE__, "memc_read: write failed, %d, %m",
					errno);
			return MEMC_SERVER_ERROR;
		}

		/* Read reply from server */
		retries = 0;
		if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
			memc_log (ctx, __LINE__, "memc_read: timeout waiting reply");
			return MEMC_SERVER_TIMEOUT;
		}
		r = read (ctx->sock, read_buf, READ_BUFSIZ - 1);

		if (r > 0) {
			sum += r;
			read_buf[r] = 0;
			r = memc_parse_header (read_buf, &datalen, &p);
			if (r < 0) {
				memc_log (ctx, __LINE__,
						"memc_read: cannot parse memcached reply");
				return MEMC_SERVER_ERROR;
			}
			else if (r == 0) {
				memc_log (ctx, __LINE__, "memc_read: record does not exists");
				return MEMC_NOT_EXISTS;
			}

			if (datalen != params[i].bufsize) {
#ifndef FREEBSD_LEGACY
				memc_log (ctx, __LINE__,
						"memc_read: user's buffer is too small: %zd, %zd required",
						params[i].bufsize, datalen);
#else
				memc_log (ctx, __LINE__, "memc_read: user's buffer is too small: %ld, %ld required", (long int)params[i].bufsize,
						(long int)datalen);
#endif
				return MEMC_WRONG_LENGTH;
			}

			/* Subtract from sum parsed header's length */
			sum -= p - read_buf;
			/* Check if we already have all data in buffer */
			if ((size_t) sum
					>= datalen + sizeof(END_TRAILER) + sizeof(CRLF) - 2) {
				/* Store all data in param's buffer */
				memcpy(params[i].buf, p, datalen);
				/* Increment count */
				ctx->count++;
				return MEMC_OK;
			}
			else {
				/* Store this part of data in param's buffer */
				memcpy(params[i].buf, p, sum);
				written += sum;
			}
		}
		else {
			memc_log (ctx, __LINE__, "memc_read: read(v) failed: %d, %m", r);
			return MEMC_SERVER_ERROR;
		}
		/* Read data from multiply datagrams */
		p = read_buf;

		while ((size_t) sum < datalen + sizeof(END_TRAILER) + sizeof(CRLF) - 2) {
			retries = 0;
			if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
				memc_log (ctx, __LINE__,
						"memc_read: timeout waiting reply");
				return MEMC_SERVER_TIMEOUT;
			}
			r = read (ctx->sock, read_buf, READ_BUFSIZ - 1);

			p = read_buf;
			sum += r;
			if (r <= 0) {
				break;
			}
			/* Copy received buffer to result buffer */
			while (r--) {
				/* Break on reading END\r\n */
				if (strncmp (p, END_TRAILER, sizeof(END_TRAILER) - 1) == 0) {
					break;
				}
				if ((size_t) written < datalen) {
					params[i].buf[written++] = *p++;
				}
			}
		}
		/* Increment count */
		ctx->count++;
	}

	return MEMC_OK;
}

/*
 * Common write command handler for memcached
 */
memc_error_t memc_write(memcached_ctx_t *ctx, const char *cmd,
		memcached_param_t *params, size_t *nelem, int expire)
{
	char read_buf[READ_BUFSIZ];
	unsigned int i, retries, ofl;
	ssize_t r;
	struct iovec iov[4];

	for (i = 0; i < *nelem; i++) {

		r = snprintf(read_buf, READ_BUFSIZ, "%s %s 0 %d %u" CRLF, cmd,
				params[i].key, expire, (unsigned)params[i].bufsize);
		memc_log (ctx, __LINE__,
				"memc_write: send write request to memcached: %s", read_buf);
		/* Set socket blocking */
		ofl = fcntl (ctx->sock, F_GETFL, 0);
		fcntl (ctx->sock, F_SETFL, ofl & (~O_NONBLOCK));

		iov[0].iov_base = read_buf;
		iov[0].iov_len = r;
		iov[1].iov_base = params[i].buf;
		iov[1].iov_len = params[i].bufsize;
		iov[2].iov_base = CRLF;
		iov[2].iov_len = sizeof(CRLF) - 1;
		if (writev (ctx->sock, iov, 3) == -1) {
			memc_log (ctx, __LINE__, "memc_write: writev failed, %d, %m",
					errno);
			return MEMC_SERVER_ERROR;
		}
		/* Restore socket mode */
		fcntl (ctx->sock, F_SETFL, ofl);
		/* Read reply from server */
		if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
			memc_log (ctx, __LINE__,
					"memc_write: server timeout while reading reply");
			return MEMC_SERVER_ERROR;
		}
		/* Read header */
		retries = 0;
		if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
			memc_log (ctx, __LINE__, "memc_write: timeout waiting reply");
			return MEMC_SERVER_TIMEOUT;
		}
		r = read (ctx->sock, read_buf, READ_BUFSIZ - 1);
		/* Increment count */
		ctx->count++;

		if (strncmp (read_buf, STORED_TRAILER, sizeof(STORED_TRAILER) - 1)
				== 0) {
			continue;
		}
		else if (strncmp (read_buf, NOT_STORED_TRAILER,
				sizeof(NOT_STORED_TRAILER) - 1) == 0) {
			return MEMC_CLIENT_ERROR;
		}
		else if (strncmp (read_buf, EXISTS_TRAILER, sizeof(EXISTS_TRAILER) - 1)
				== 0) {
			return MEMC_EXISTS;
		}
		else {
			return MEMC_SERVER_ERROR;
		}
	}

	return MEMC_OK;
}
/*
 * Delete command handler
 */
memc_error_t memc_delete(memcached_ctx_t *ctx, memcached_param_t *params,
		size_t *nelem)
{
	char read_buf[READ_BUFSIZ];
	unsigned int i, retries;
	ssize_t r;
	struct iovec iov[2];

	for (i = 0; i < *nelem; i++) {
		r = snprintf(read_buf, READ_BUFSIZ, "delete %s" CRLF, params[i].key);
		memc_log (ctx, __LINE__,
				"memc_delete: send delete request to memcached: %s", read_buf);
		if (write (ctx->sock, read_buf, r) == -1) {
			memc_log (ctx, __LINE__, "memc_delete: write failed, %d, %m",
					errno);
			return MEMC_SERVER_ERROR;
		}

		/* Read reply from server */
		retries = 0;
		if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
			return MEMC_SERVER_TIMEOUT;
		}
		r = read (ctx->sock, read_buf, READ_BUFSIZ - 1);

		/* Increment count */
		ctx->count++;
		if (strncmp (read_buf, DELETED_TRAILER, sizeof(DELETED_TRAILER) - 1)
				== 0) {
			continue;
		}
		else if (strncmp (read_buf, NOT_FOUND_TRAILER,
				sizeof(NOT_FOUND_TRAILER) - 1) == 0) {
			return MEMC_NOT_EXISTS;
		}
		else {
			return MEMC_SERVER_ERROR;
		}
	}

	return MEMC_OK;
}

/*
 * Write handler for memcached mirroring
 * writing is done to each memcached server
 */
memc_error_t memc_write_mirror(memcached_ctx_t *ctx, size_t memcached_num,
		const char *cmd, memcached_param_t *params, size_t *nelem, int expire)
{
	memc_error_t r, result = MEMC_OK;

	while (memcached_num--) {
		if (ctx[memcached_num].alive == 1) {
			r = memc_write (&ctx[memcached_num], cmd, params, nelem, expire);
			if (r != MEMC_OK) {
				memc_log (&ctx[memcached_num], __LINE__,
						"memc_write_mirror: cannot write to mirror server: %s",
						memc_strerror (r));
				result = r;
				ctx[memcached_num].alive = 0;
			}
		}
	}

	return result;
}

/*
 * Read handler for memcached mirroring
 * reading is done from first active memcached server
 */
memc_error_t memc_read_mirror(memcached_ctx_t *ctx, size_t memcached_num,
		const char *cmd, memcached_param_t *params, size_t *nelem)
{
	memc_error_t r, result = MEMC_OK;

	while (memcached_num--) {
		if (ctx[memcached_num].alive == 1) {
			r = memc_read (&ctx[memcached_num], cmd, params, nelem);
			if (r != MEMC_OK) {
				result = r;
				if (r != MEMC_NOT_EXISTS) {
					ctx[memcached_num].alive = 0;
					memc_log (&ctx[memcached_num], __LINE__,
							"memc_read_mirror: cannot write read from mirror server: %s",
							memc_strerror (r));
				}
				else {
					memc_log (&ctx[memcached_num], __LINE__,
							"memc_read_mirror: record not exists",
							memc_strerror (r));
				}
			}
			else {
				break;
			}
		}
	}

	return result;
}

/*
 * Delete handler for memcached mirroring
 * deleting is done for each active memcached server
 */
memc_error_t memc_delete_mirror(memcached_ctx_t *ctx, size_t memcached_num,
		const char *cmd, memcached_param_t *params, size_t *nelem)
{
	memc_error_t r, result = MEMC_OK;

	while (memcached_num--) {
		if (ctx[memcached_num].alive == 1) {
			r = memc_delete (&ctx[memcached_num], params, nelem);
			if (r != MEMC_OK) {
				result = r;
				if (r != MEMC_NOT_EXISTS) {
					ctx[memcached_num].alive = 0;
					memc_log (&ctx[memcached_num], __LINE__,
							"memc_delete_mirror: cannot delete from mirror server: %s",
							memc_strerror (r));
				}
			}
		}
	}

	return result;
}

int memc_init_ctx(memcached_ctx_t *ctx)
{
	if (ctx == NULL) {
		return -1;
	}

	ctx->count = 0;
	ctx->alive = 1;

	return memc_make_tcp_sock (ctx);
}
/*
 * Mirror init
 */
int memc_init_ctx_mirror(memcached_ctx_t *ctx, size_t memcached_num)
{
	int r, result = -1;
	while (memcached_num--) {
		if (ctx[memcached_num].alive == 1) {
			r = memc_init_ctx (&ctx[memcached_num]);
			if (r == -1) {
				ctx[memcached_num].alive = 0;
				memc_log (&ctx[memcached_num], __LINE__,
						"memc_init_ctx_mirror: cannot connect to server");
			}
			else {
				result = 1;
			}
		}
		else {
			ctx[memcached_num].opened = 0;
		}
	}

	return result;
}

/*
 * Close context connection
 */
int memc_close_ctx(memcached_ctx_t *ctx)
{
	int fd;

	if (!ctx->opened) {
		return 0;
	}

	if (ctx != NULL && ctx->sock != -1) {
		fd = ctx->sock;
		ctx->sock = -1;
		ctx->opened = 0;
		return close (fd);
	}

	return -1;
}
/* 
 * Mirror close
 */
int memc_close_ctx_mirror(memcached_ctx_t *ctx, size_t memcached_num)
{
	int r = 0;
	while (memcached_num--) {
		r = memc_close_ctx (&ctx[memcached_num]);
		if (r == -1) {
			memc_log (&ctx[memcached_num], __LINE__,
					"memc_close_ctx_mirror: cannot close connection to server properly");
			ctx[memcached_num].alive = 0;
		}
	}

	return r;
}

const char * memc_strerror(memc_error_t err)
{
	const char *p;

	switch (err) {
	case MEMC_OK:
		p = "Ok";
		break;
	case MEMC_BAD_COMMAND:
		p = "Bad command";
		break;
	case MEMC_CLIENT_ERROR:
		p = "Client error";
		break;
	case MEMC_SERVER_ERROR:
		p = "Server error";
		break;
	case MEMC_SERVER_TIMEOUT:
		p = "Server timeout";
		break;
	case MEMC_NOT_EXISTS:
		p = "Key not found";
		break;
	case MEMC_EXISTS:
		p = "Key already exists";
		break;
	case MEMC_WRONG_LENGTH:
		p = "Wrong result length";
		break;
	default:
		p = "Unknown error";
		break;
	}

	return p;
}

/* 
 * vi:ts=4 
 */
