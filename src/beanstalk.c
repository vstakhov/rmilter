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

#ifdef _THREAD_SAFE
#include <pthread.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <syslog.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/uio.h>

#include "beanstalk.h"

#define CRLF "\r\n"
#define RESERVED_TRAILER "RESERVED %d %zd\r\n" CRLF
#define PEEK_TRAILER "FOUND %d %d %zd\r\n" CRLF
#define STORED_TRAILER "INSERTED %d" CRLF
#define NOT_STORED_TRAILER "BURIED %d" CRLF
#define BURIED_TRAILER "BURIED" CRLF
#define RELEASED_TRAILER "RELEASED" CRLF
#define EXISTS_TRAILER "EXISTS" CRLF
#define DELETED_TRAILER "DELETED" CRLF
#define KICKED_TRAILER "KICKED %zd" CRLF
#define NOT_FOUND_TRAILER "NOT_FOUND" CRLF
#define CLIENT_ERROR_TRAILER "CLIENT_ERROR"
#define SERVER_ERROR_TRAILER "SERVER_ERROR"

#define UDP_BUFSIZ 1500
#define MAX_RETRIES 3


/* XXX: actually I think beanstalkd requires same patches as memcached does to work with udp */
/* Header for udp protocol */
struct bean_udp_header
{
	uint16_t req_id;
	uint16_t seq_num;
	uint16_t dg_sent;
	uint16_t unused;
};

/*
 * Poll file descriptor for read or write during specified timeout
 */
static int
poll_d (int fd, u_char want_read, u_char want_write, int timeout)
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
	while ((r = poll(fds, 1, timeout)) < 0) {
		if (errno != EINTR)
	    	break;
    }

	return r;
}

/*
 * Make socket for udp connection
 */
static int
bean_make_udp_sock (beanstalk_ctx_t *ctx)
{
	struct sockaddr_in sc;
	int ofl;

	bzero (&sc, sizeof (struct sockaddr_in *));
	sc.sin_family = AF_INET;
	sc.sin_port = ctx->port;
	memcpy (&sc.sin_addr, &ctx->addr, sizeof (struct in_addr));

	ctx->sock = socket (PF_INET, SOCK_DGRAM, 0);

	if (ctx->sock == -1) {
		return -1;
	}

	/* set nonblocking */
    ofl = fcntl(ctx->sock, F_GETFL, 0);
    fcntl(ctx->sock, F_SETFL, ofl | O_NONBLOCK);

	/* 
	 * Call connect to set default destination for datagrams 
	 * May not block
	 */
	return connect (ctx->sock, (struct sockaddr*)&sc, sizeof (struct sockaddr_in));
}

/*
 * Make socket for tcp connection
 */
static int
bean_make_tcp_sock (beanstalk_ctx_t *ctx)
{
	struct sockaddr_in sc;
	int ofl, r;

	bzero (&sc, sizeof (struct sockaddr_in *));
	sc.sin_family = AF_INET;
	sc.sin_port = ctx->port;
	memcpy (&sc.sin_addr, &ctx->addr, sizeof (struct in_addr));

	ctx->sock = socket (PF_INET, SOCK_STREAM, 0);

	if (ctx->sock == -1) {
		return -1;
	}

	/* set nonblocking */
    ofl = fcntl(ctx->sock, F_GETFL, 0);
    fcntl(ctx->sock, F_SETFL, ofl | O_NONBLOCK);
	
	if ((r = connect (ctx->sock, (struct sockaddr*)&sc, sizeof (struct sockaddr_in))) == -1) {
		if (errno != EINPROGRESS) {
			return -1;
		}
	}
	/* Get write readiness */
	if (poll_d (ctx->sock, 0, 1, ctx->timeout) == 1) {
		return 0;
	} 
	else {
		close (ctx->sock);
		return -1;
	}
}

/* 
 * Parse VALUE reply from server and set len argument to value returned by beanstalk 
 */
static int
bean_parse_header (char *buf, beanstalk_param_t *param, char **end, const char *format)
{
	char *c;
	int r;

	c = strstr (buf, CRLF);
	if (c == NULL) {
		return -1;
	}
	*end = c + sizeof (CRLF) - 1;
	
	r = sscanf (buf, format, &param->id, &param->len);
	if (r == EOF) {
		return -1;
	}
	return r;
}
/*
 * Common read command handler for beanstalk
 */
bean_error_t
bean_read (beanstalk_ctx_t *ctx, beanstalk_cmd_t cmd, beanstalk_param_t *params, size_t *nelem, u_int wait)
{
	char udp_buf[UDP_BUFSIZ];
	char *p;
	int i, retries;
	ssize_t r, sum = 0, written = 0;
	size_t datalen;
	struct bean_udp_header header;
	struct iovec iov[2];
	
	for (i = 0; i < *nelem; i++) {
		if (ctx->protocol == BEANSTALK_UDP_TEXT) {
			/* Send udp header */
			bzero (&header, sizeof (header));
			header.dg_sent = htons (1);
			header.req_id = ctx->count;
		}
		switch (cmd) {
			case BEANSTALK_CMD_RESERVE:
				r = snprintf (udp_buf, UDP_BUFSIZ, "reserve" CRLF);
				break;
			case BEANSTALK_CMD_PEEK:
				if (params[i].id == 0) {
					r = snprintf (udp_buf, UDP_BUFSIZ, "peek" CRLF);
				}
				else {
					r = snprintf (udp_buf, UDP_BUFSIZ, "peek %d" CRLF, params[i].id);
				}
				break;
			default:
				return BEANSTALK_BAD_COMMAND;
		}
		if (ctx->protocol == BEANSTALK_UDP_TEXT) {
			iov[0].iov_base = &header;
			iov[0].iov_len = sizeof (struct bean_udp_header);
			iov[1].iov_base = udp_buf;
			iov[1].iov_len = r;
			writev (ctx->sock, iov, 2);
		}
		else {
			write (ctx->sock, udp_buf, r);
		}

		/* Read reply from server */
		retries = 0;
		while (ctx->protocol == BEANSTALK_UDP_TEXT) {
			if (poll_d (ctx->sock, 1, 0, wait) != 1) {
				return BEANSTALK_SERVER_TIMEOUT;
			}
			iov[0].iov_base = &header;
			iov[0].iov_len = sizeof (struct bean_udp_header);
			iov[1].iov_base = udp_buf;
			iov[1].iov_len = UDP_BUFSIZ;
			if ((r = readv (ctx->sock, iov, 2)) == -1) {
				return BEANSTALK_SERVER_ERROR;
			}
			if (header.req_id != ctx->count && retries < MAX_RETRIES) {
				retries++;
				/* Not our reply packet */
				continue;
			}
			break;
		}
		if (ctx->protocol != BEANSTALK_UDP_TEXT) {
			if (poll_d (ctx->sock, 1, 0, wait) != 1) {
				return BEANSTALK_SERVER_TIMEOUT;
			}
			r = read (ctx->sock, udp_buf, UDP_BUFSIZ - 1);
		}

		if (r > 0) {
			sum += r;
			udp_buf[r] = 0;
			if (cmd == BEANSTALK_CMD_RESERVE) {
				r = bean_parse_header (udp_buf, &params[i], &p, RESERVED_TRAILER);
			}
			else {
				r = bean_parse_header (udp_buf, &params[i], &p, PEEK_TRAILER);
			}
			datalen = params[i].len;

			if (r < 0) {
				return BEANSTALK_SERVER_ERROR;
			}
			else if (r == 0) {
				return BEANSTALK_NOT_EXISTS;
			}

			if (datalen > params[i].bufsize) {
				return BEANSTALK_WRONG_LENGTH;
			}

			/* Subtract from sum parsed header's length */
			sum -= p - udp_buf;
			/* Check if we already have all data in buffer */
			if (sum >= datalen + sizeof (CRLF) - 2) {
				/* Store all data in param's buffer */
				memcpy (params[i].buf, p, datalen);
				/* Increment count */
				ctx->count++;
				return BEANSTALK_OK;
			}
			else {
				/* Store this part of data in param's buffer */
				memcpy (p, params[i].buf, sum);
				written += sum;
			}
		}
		else {
			return BEANSTALK_SERVER_ERROR;
		}
		/* Read data from multiply datagrams */
		p = udp_buf;

		while (sum < datalen + sizeof (CRLF) - 2) {
			retries = 0;
			while (ctx->protocol == BEANSTALK_UDP_TEXT) {
				if (poll_d (ctx->sock, 1, 0, wait) != 1) {
					return BEANSTALK_SERVER_TIMEOUT;
				}
				iov[0].iov_base = &header;
				iov[0].iov_len = sizeof (struct bean_udp_header);
				iov[1].iov_base = udp_buf;
				iov[1].iov_len = UDP_BUFSIZ;
				if ((r = readv (ctx->sock, iov, 2)) == -1) {
					return BEANSTALK_SERVER_ERROR;
				}
				if (header.req_id != ctx->count && retries < MAX_RETRIES) {
					retries ++;
					/* Not our reply packet */
					continue;
				}
			}
			if (ctx->protocol != BEANSTALK_UDP_TEXT) {
				if (poll_d (ctx->sock, 1, 0, wait) != 1) {
					return BEANSTALK_SERVER_TIMEOUT;
				}
				r = read (ctx->sock, udp_buf, UDP_BUFSIZ - 1);
			}

			sum += r;
			if (r <= 0) {
				break;
			}
			/* Copy received buffer to result buffer */
			while (r--) {
				/* Break on reading CRLF */
				if (*p == '\r' && *p == '\n') {
					break;
				}
				if (written < datalen) {
					params[i].buf[written] = *p;
				}
			}
		}
		/* Increment count */
		ctx->count++;
	}

	return BEANSTALK_OK;
}

/*
 * Common write command handler for beanstalk
 */
bean_error_t
bean_write (beanstalk_ctx_t *ctx, beanstalk_cmd_t cmd, beanstalk_param_t *params, size_t *nelem, u_int ttr, u_int delay)
{
	char udp_buf[UDP_BUFSIZ];
	int i, retries;
	ssize_t r;
	struct bean_udp_header header;
	struct iovec iov[4];
	
	for (i = 0; i < *nelem; i++) {
		if (ctx->protocol == BEANSTALK_UDP_TEXT) {
			/* Send udp header */
			bzero (&header, sizeof (header));
			header.dg_sent = htons (1);
			header.req_id = ctx->count;
		}

		switch (cmd) {
			case BEANSTALK_CMD_PUT:
				r = snprintf (udp_buf, UDP_BUFSIZ, "put %d %d %d %zd" CRLF, 
								params[i].priority, delay, ttr, params[i].bufsize);
				break;
			default:
				return BEANSTALK_BAD_COMMAND;
		}

		if (ctx->protocol == BEANSTALK_UDP_TEXT) {
			iov[0].iov_base = &header;
			iov[0].iov_len = sizeof (struct bean_udp_header);
			iov[1].iov_base = udp_buf;
			iov[1].iov_len = r;
			iov[2].iov_base = params[i].buf;
			iov[2].iov_len = params[i].bufsize;
			iov[3].iov_base = CRLF;
			iov[3].iov_len = sizeof (CRLF) - 1;
			writev (ctx->sock, iov, 4);
		}
		else {
			iov[0].iov_base = udp_buf;
			iov[0].iov_len = r;
			iov[1].iov_base = params[i].buf;
			iov[1].iov_len = params[i].bufsize;
			iov[2].iov_base = CRLF;
			iov[2].iov_len = sizeof (CRLF) - 1;
			writev (ctx->sock, iov, 3);	
		}

		/* Read reply from server */
		if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
			return BEANSTALK_SERVER_ERROR;
		}
		/* Read header */
		retries = 0;
		while (ctx->protocol == BEANSTALK_UDP_TEXT) {
			if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
				return BEANSTALK_SERVER_TIMEOUT;
			}
			iov[0].iov_base = &header;
			iov[0].iov_len = sizeof (struct bean_udp_header);
			iov[1].iov_base = udp_buf;
			iov[1].iov_len = UDP_BUFSIZ;
			if ((r = readv (ctx->sock, iov, 2)) == -1) {
				return BEANSTALK_SERVER_ERROR;
			}
			if (header.req_id != ctx->count && retries < MAX_RETRIES) {
				retries ++;
				/* Not our reply packet */
				continue;
			}
			break;
		}
		if (ctx->protocol != BEANSTALK_UDP_TEXT) {
			if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
				return BEANSTALK_SERVER_TIMEOUT;
			}
			r = read (ctx->sock, udp_buf, UDP_BUFSIZ - 1);
		}
		/* Increment count */
		ctx->count++;
		
		if (sscanf (udp_buf, STORED_TRAILER, &params[i].id) != EOF) {
			return BEANSTALK_OK;
		}
		else if (sscanf (udp_buf, STORED_TRAILER, &params[i].id) != EOF) {
			return BEANSTALK_BURIED;
		}
		else {
			return BEANSTALK_SERVER_ERROR;
		}
	}

	return BEANSTALK_OK;
}
/*
 * Delete command handler
 */
bean_error_t
bean_del (beanstalk_ctx_t *ctx, beanstalk_cmd_t cmd, beanstalk_param_t *params, size_t nelem, u_int delay)
{
	char udp_buf[UDP_BUFSIZ];
	int retries;
	ssize_t r;
	struct bean_udp_header header;
	struct iovec iov[2];
	
	if (ctx->protocol == BEANSTALK_UDP_TEXT) {
		/* Send udp header */
		bzero (&header, sizeof (header));
		header.dg_sent = htons(1);
		header.req_id = ctx->count;
	}

	switch (cmd) {
		case BEANSTALK_CMD_DELETE:
			r = snprintf (udp_buf, UDP_BUFSIZ, "delete %d" CRLF, params->id);
			break;
		case BEANSTALK_CMD_BURY:
			r = snprintf (udp_buf, UDP_BUFSIZ, "bury %d %d" CRLF, params->id, params->priority);
			break;
		case BEANSTALK_CMD_RELEASE:
			r = snprintf (udp_buf, UDP_BUFSIZ, "release %d %d %d" CRLF, params->id, params->priority, delay);
			break;
		case BEANSTALK_CMD_KICK:
			r = snprintf (udp_buf, UDP_BUFSIZ, "kick %zd" CRLF, nelem);
			break;
		default:
			return BEANSTALK_BAD_COMMAND;
	}

	if (ctx->protocol == BEANSTALK_UDP_TEXT) {
		iov[0].iov_base = &header;
		iov[0].iov_len = sizeof (struct bean_udp_header);
		iov[1].iov_base = udp_buf;
		iov[1].iov_len = r;
		writev (ctx->sock, iov, 2);
	}
	else {
		write (ctx->sock, udp_buf, r);
	}

	/* Read reply from server */
	retries = 0;
	while (ctx->protocol == BEANSTALK_UDP_TEXT) {
		if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
			return BEANSTALK_SERVER_TIMEOUT;
		}
		iov[0].iov_base = &header;
		iov[0].iov_len = sizeof (struct bean_udp_header);
		iov[1].iov_base = udp_buf;
		iov[1].iov_len = UDP_BUFSIZ;
		if ((r = readv (ctx->sock, iov, 2)) == -1) {
			return BEANSTALK_SERVER_ERROR;
		}
		if (header.req_id != ctx->count && retries < MAX_RETRIES) {
			retries ++;
			/* Not our reply packet */
			continue;
		}
		break;
	}
	if (ctx->protocol != BEANSTALK_UDP_TEXT) {
		if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
			return BEANSTALK_SERVER_TIMEOUT;
		}
		r = read (ctx->sock, udp_buf, UDP_BUFSIZ - 1);
	}
	
	/* Increment count */
	ctx->count++;
	switch (cmd) {
		case BEANSTALK_CMD_DELETE:	
			if (strncmp (udp_buf, DELETED_TRAILER, sizeof (DELETED_TRAILER) - 1) == 0) {
				return BEANSTALK_OK;
			}
			else if (strncmp (udp_buf, NOT_FOUND_TRAILER, sizeof (NOT_FOUND_TRAILER) - 1) == 0) {
				return BEANSTALK_NOT_EXISTS;
			}
			else {
				return BEANSTALK_SERVER_ERROR;
			}
			break;
		case BEANSTALK_CMD_BURY:
			if (strncmp (udp_buf, BURIED_TRAILER, sizeof (BURIED_TRAILER) - 1) == 0) {
				return BEANSTALK_OK;
			}
			else if (strncmp (udp_buf, NOT_FOUND_TRAILER, sizeof (NOT_FOUND_TRAILER) - 1) == 0) {
				return BEANSTALK_NOT_EXISTS;
			}
			else {
				return BEANSTALK_SERVER_ERROR;
			}
			break;
		case BEANSTALK_CMD_RELEASE:
			if (strncmp (udp_buf, RELEASED_TRAILER, sizeof (RELEASED_TRAILER) - 1) == 0) {
				return BEANSTALK_OK;
			}
			else if (strncmp (udp_buf, BURIED_TRAILER, sizeof (BURIED_TRAILER) - 1) == 0) {
				return BEANSTALK_BURIED;
			}
			else if (strncmp (udp_buf, NOT_FOUND_TRAILER, sizeof (NOT_FOUND_TRAILER) - 1) == 0) {
				return BEANSTALK_NOT_EXISTS;
			}
			else {
				return BEANSTALK_SERVER_ERROR;
			}
			break;
		case BEANSTALK_CMD_KICK:
			if (sscanf (udp_buf, KICKED_TRAILER, &r) != EOF && r == nelem) {
				return BEANSTALK_OK;
			}
			else {
				return BEANSTALK_CLIENT_ERROR;
			}
			break;
		default:
			return BEANSTALK_BAD_COMMAND;
	}

	return BEANSTALK_OK;
}

/* 
 * Initialize beanstalk context for specified protocol
 */
int 
bean_init_ctx (beanstalk_ctx_t *ctx)
{
	if (ctx == NULL) {
		return -1;
	}

	ctx->count = 0;

	switch (ctx->protocol) {
		case BEANSTALK_UDP_TEXT:
			return bean_make_udp_sock (ctx);
			break;
		case BEANSTALK_TCP_TEXT:
			return bean_make_tcp_sock (ctx);
			break;
		/* Not implemented */
		case BEANSTALK_UDP_BIN:
		case BEANSTALK_TCP_BIN:
		default:
			return -1;
	}
}

/*
 * Close context connection
 */
int
bean_close_ctx (beanstalk_ctx_t *ctx)
{
	if (ctx != NULL && ctx->sock != -1) {
		close (ctx->sock);
	}

	return 0;
}

const char * bean_strerror (bean_error_t err)
{
	const char *p;

	switch (err) {
		case BEANSTALK_OK:
			p = "Ok";
			break;
		case BEANSTALK_BAD_COMMAND:
			p = "Bad command";
			break;
		case BEANSTALK_CLIENT_ERROR:
			p = "Client error";
			break;
		case BEANSTALK_SERVER_ERROR:
			p = "Server error";
			break;
		case BEANSTALK_SERVER_TIMEOUT:
			p = "Server timeout";
			break;
		case BEANSTALK_NOT_EXISTS:
			p = "Key not found";
			break;
		case BEANSTALK_EXISTS:
			p = "Key already exists";
			break;
		case BEANSTALK_WRONG_LENGTH:
			p = "Wrong result length";
			break;
		case BEANSTALK_BURIED:
			p = "Priority queue is full, message buried";
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
