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

#include "memcached.h"

#define CRLF "\r\n"
#define END_TRAILER "END" CRLF
#define STORED_TRAILER "STORED" CRLF
#define NOT_STORED_TRAILER "NOT STORED" CRLF
#define EXISTS_TRAILER "EXISTS" CRLF
#define CLIENT_ERROR_TRAILER "CLIENT_ERROR"
#define SERVER_ERROR_TRAILER "SERVER_ERROR"

#define UDP_BUFSIZ 1500

/* Header for udp protocol */
struct memc_udp_header
{
	uint16_t req_id;
	uint16_t seq_num;
	uint16_t dg_sent;
	uint16_t unused;
};

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

static int
memc_make_udp_sock (memcached_ctx_t *ctx)
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

static int
memc_read_udp_header (memcached_ctx_t *ctx, struct memc_udp_header *header)
{
	ssize_t r;

	/* Read udp header */
	if ((r = poll_d (ctx->sock, 1, 0, ctx->timeout)) != -1) {
		r = recv (ctx->sock, header, sizeof (struct memc_udp_header), 0);
	}
	if (r == -1) {
		return -1;
	}

	return 0;
}

static int
memc_write_udp_header (memcached_ctx_t *ctx, struct memc_udp_header *header)
{
	return send (ctx->sock, header, sizeof (struct memc_udp_header), 0);
}

/* Parse VALUE reply from server and set len argument to value returned by memcached */
static int
memc_parse_header (char *buf, size_t *len, char **end)
{
	char *p, *c;
	int i;

	/* VALUE <key> <flags> <bytes> [<cas unique>]\r\n */
	c = strstr (buf, CRLF);
	if (c == NULL) {
		return -1;
	}
	*end = c + sizeof (CRLF) - 1;
	
	if (strncmp (buf, "VALUE ", sizeof ("VALUE ") - 1) == 0) {
		p = buf + sizeof ("VALUE ") - 1;
	
		/* Read bytes value and ignore all other fields, such as flags and key */
		for (i = 0; i < 2; i++) {
			while (p++ < c && *p != ' ');

			if (p > c) {
				return -1;
			}
		}
		*len = strtoul (p, &c, 10);
		return 1;
	}
	/* If value not found memcached return just END\r\n , in this case return 0 */
	else if (strncmp (buf, END_TRAILER, sizeof (END_TRAILER) - 1) == 0) {
		return 0;
	}

	return -1;
}

memc_error_t
memc_read (memcached_ctx_t *ctx, const char *cmd, memcached_param_t *params, size_t *nelem)
{
	char udp_buf[UDP_BUFSIZ];
	char *p;
	int i;
	ssize_t r, sum = 0, written = 0;
	size_t datalen;
	struct memc_udp_header header;
	
	for (i = 0; i < *nelem; i++) {
		if (ctx->protocol == UDP_TEXT) {
			/* Send udp header */
			bzero (&header, sizeof (header));
			memc_write_udp_header (ctx, &header);
		}

		r = snprintf (udp_buf, UDP_BUFSIZ, "%s %s" CRLF, cmd, params[i].key);
		send (ctx->sock, udp_buf, i + 1, 0);

		/* Read reply from server */
		/* Read header */
		if (ctx->protocol == UDP_TEXT) {
			if (memc_read_udp_header (ctx, &header) == -1) {
				return SERVER_ERROR;
			}
		}
		r = recv (ctx->sock, udp_buf, UDP_BUFSIZ - 1, 0);
		if (r > 0) {
			sum += r;
			udp_buf[r] = 0;
			r = memc_parse_header (udp_buf, &datalen, &p);
			if (r < 0) {
				return SERVER_ERROR;
			}
			else if (r == 0) {
				return NOT_EXISTS;
			}

			if (datalen != params[i].bufsize) {
				return WRONG_LENGTH;
			}

			/* Subtract from sum parsed header's length */
			sum -= p - udp_buf;
			/* Check if we already have all data in buffer */
			if (sum >= datalen + sizeof (END_TRAILER) + sizeof (CRLF) - 2) {
				/* Store all data in param's buffer */
				memcpy (p, params[i].buf, datalen);
				return OK;
			}
			else {
				/* Store this part of data in param's buffer */
				memcpy (p, params[i].buf, sum);
				written += sum;
			}
		}
		else {
			return SERVER_ERROR;
		}
		/* Read data from multiply datagrams */
		p = udp_buf;

		while (sum < datalen + sizeof (END_TRAILER) + sizeof (CRLF) - 2) {
			/* Read header */
			if (ctx->protocol == UDP_TEXT) {
				if (memc_read_udp_header (ctx, &header) == -1) {
					return SERVER_ERROR;
				}
			}

			r = recv (ctx->sock, p, UDP_BUFSIZ - 1, 0);
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
	}

	return OK;
}

memc_error_t
memc_write (memcached_ctx_t *ctx, const char *cmd, memcached_param_t *params, size_t *nelem, int expire)
{
	char udp_buf[UDP_BUFSIZ];
	int i;
	ssize_t r;
	struct memc_udp_header header;
	
	for (i = 0; i < *nelem; i++) {
		if (ctx->protocol == UDP_TEXT) {
			/* Send udp header */
			bzero (&header, sizeof (header));
			memc_write_udp_header (ctx, &header);
		}

		r = snprintf (udp_buf, UDP_BUFSIZ, "%s %s 0 %d %zu" CRLF, cmd, params[i].key, expire, params[i].bufsize);
		send (ctx->sock, udp_buf, i + 1, 0);
		
		/* Send all other data */
		r = send (ctx->sock, params[i].buf, params[i].bufsize, 0);
		/* Read reply from server */
		/* Read header */
		if (ctx->protocol == UDP_TEXT) {
			if (memc_read_udp_header (ctx, &header) == -1) {
				return SERVER_ERROR;
			}
		}
		r = recv (ctx->sock, udp_buf, UDP_BUFSIZ - 1, 0);
		
		if (strncmp (udp_buf, STORED_TRAILER, sizeof (STORED_TRAILER) - 1) == 0) {
			continue;
		}
		else if (strncmp (udp_buf, NOT_STORED_TRAILER, sizeof (NOT_STORED_TRAILER) - 1) == 0) {
			return CLIENT_ERROR;
		}
		else if (strncmp (udp_buf, EXISTS_TRAILER, sizeof (EXISTS_TRAILER) - 1) == 0) {
			return EXISTS;
		}
		else {
			return SERVER_ERROR;
		}
	}

	return OK;
}

int 
memc_init_ctx (memcached_ctx_t *ctx)
{
	if (ctx == NULL) {
		return -1;
	}

	switch (ctx->protocol) {
		case UDP_TEXT:
			return memc_make_udp_sock (ctx);
			break;
		/* Not implemented */
		case TCP_TEXT:
		case UDP_BIN:
		case TCP_BIN:
		default:
			return -1;
	}
}

int
memc_close_ctx (memcached_ctx_t *ctx)
{
	if (ctx != NULL && ctx->sock != -1) {
		close (ctx->sock);
	}

	return 0;
}

/* 
 * vi:ts=4 
 */
