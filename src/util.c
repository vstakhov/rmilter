/* Copyright (c) 2013, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "util.h"
#include <assert.h>
#include <stdbool.h>


extern const char *_rmilter_progname;

size_t
rmilter_strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0) {
		while (--n != 0) {
			if ((*d++ = *s++) == '\0') {
				break;
			}
		}
	}

	if (n == 0 && siz != 0) {
		*d = '\0';
	}

	return (s - src - 1); /* count does not include NUL */
}

bool
rmilter_file_lock(int fd, bool async)
{
	int flags;

	if (async) {
		flags = LOCK_EX | LOCK_NB;
	}
	else {
		flags = LOCK_EX;
	}

	if (flock (fd, flags) == -1) {
		if (async && errno == EAGAIN) {
			return false;
		}

		return false;
	}

	return true;
}

bool
rmilter_file_unlock(int fd, bool async)
{
	int flags;

	if (async) {
		flags = LOCK_UN | LOCK_NB;
	}
	else {
		flags = LOCK_UN;
	}

	if (flock (fd, flags) == -1) {
		if (async && errno == EAGAIN) {
			return false;
		}

		return false;
	}

	return true;

}

static int _rmilter_pidfile_remove(rmilter_pidfh_t *pfh, int freeit);

static int
rmilter_pidfile_verify(rmilter_pidfh_t *pfh)
{
	struct stat sb;

	if (pfh == NULL || pfh->pf_fd == -1)
		return (-1);
	/*
	 * Check remembered descriptor.
	 */
	if (fstat (pfh->pf_fd, &sb) == -1)
		return (errno);
	if (sb.st_dev != pfh->pf_dev || sb.st_ino != pfh->pf_ino)
		return -1;
	return 0;
}

static int
rmilter_pidfile_read(const char *path, pid_t * pidptr)
{
	char buf[16], *endptr;
	int error, fd, i;

	fd = open (path, O_RDONLY);
	if (fd == -1)
		return (errno);

	i = read (fd, buf, sizeof(buf) - 1);
	error = errno; /* Remember errno in case close() wants to change it. */
	close (fd);
	if (i == -1)
		return error;
	else if (i == 0)
		return EAGAIN;
	buf[i] = '\0';

	*pidptr = strtol (buf, &endptr, 10);
	if (endptr != &buf[i])
		return EINVAL;

	return 0;
}

rmilter_pidfh_t *
rmilter_pidfile_open(const char *path, mode_t mode, pid_t * pidptr)
{
	rmilter_pidfh_t *pfh;
	struct stat sb;
	int error, fd, len, count;
	struct timespec rqtp;

	pfh = malloc (sizeof(*pfh));
	if (pfh == NULL)
		return NULL;

	if (path == NULL)
		len = snprintf(pfh->pf_path, sizeof(pfh->pf_path), "/var/run/%s.pid",
				_rmilter_progname);
	else
		len = snprintf(pfh->pf_path, sizeof(pfh->pf_path), "%s", path);
	if (len >= (int) sizeof(pfh->pf_path)) {
		free (pfh);
		errno = ENAMETOOLONG;
		return NULL;
	}

	/*
	 * Open the PID file and obtain exclusive lock.
	 * We truncate PID file here only to remove old PID immediatelly,
	 * PID file will be truncated again in pidfile_write(), so
	 * pidfile_write() can be called multiple times.
	 */
	fd = open (pfh->pf_path, O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK, mode);
	rmilter_file_lock (fd, true);
	if (fd == -1) {
		count = 0;
		rqtp.tv_sec = 0;
		rqtp.tv_nsec = 5000000;
		if (errno == EWOULDBLOCK && pidptr != NULL) {
			again:
			errno = rmilter_pidfile_read (pfh->pf_path, pidptr);
			if (errno == 0)
				errno = EEXIST;
			else if (errno == EAGAIN) {
				if (++count <= 3) {
					nanosleep (&rqtp, 0);
					goto again;
				}
			}
		}
		free (pfh);
		return NULL;
	}
	/*
	 * Remember file information, so in pidfile_write() we are sure we write
	 * to the proper descriptor.
	 */
	if (fstat (fd, &sb) == -1) {
		error = errno;
		unlink (pfh->pf_path);
		close (fd);
		free (pfh);
		errno = error;
		return NULL;
	}

	pfh->pf_fd = fd;
	pfh->pf_dev = sb.st_dev;
	pfh->pf_ino = sb.st_ino;

	return pfh;
}

int
rmilter_pidfile_write(rmilter_pidfh_t *pfh)
{
	char pidstr[16];
	int error, fd;

	/*
	 * Check remembered descriptor, so we don't overwrite some other
	 * file if pidfile was closed and descriptor reused.
	 */
	errno = rmilter_pidfile_verify (pfh);
	if (errno != 0) {
		/*
		 * Don't close descriptor, because we are not sure if it's ours.
		 */
		return -1;
	}
	fd = pfh->pf_fd;

	/*
	 * Truncate PID file, so multiple calls of pidfile_write() are allowed.
	 */
	if (ftruncate (fd, 0) == -1) {
		error = errno;
		_rmilter_pidfile_remove (pfh, 0);
		errno = error;
		return -1;
	}

	snprintf (pidstr, sizeof(pidstr), "%ld", (long)getpid ());
	if (pwrite (fd, pidstr, strlen (pidstr), 0) != (ssize_t) strlen (pidstr)) {
		error = errno;
		_rmilter_pidfile_remove (pfh, 0);
		errno = error;
		return -1;
	}

	return 0;
}

int
rmilter_pidfile_close(rmilter_pidfh_t *pfh)
{
	int error;

	error = rmilter_pidfile_verify (pfh);
	if (error != 0) {
		errno = error;
		return -1;
	}

	if (close (pfh->pf_fd) == -1)
		error = errno;
	free (pfh);
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

static int
_rmilter_pidfile_remove(rmilter_pidfh_t *pfh, int freeit)
{
	int error;

	error = rmilter_pidfile_verify (pfh);
	if (error != 0) {
		errno = error;
		return -1;
	}

	if (unlink (pfh->pf_path) == -1)
		error = errno;
	if (!rmilter_file_unlock (pfh->pf_fd, false)) {
		if (error == 0)
			error = errno;
	}
	if (close (pfh->pf_fd) == -1) {
		if (error == 0)
			error = errno;
	}
	if (freeit)
		free (pfh);
	else
		pfh->pf_fd = -1;
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

int
rmilter_pidfile_remove(rmilter_pidfh_t *pfh)
{

	return (_rmilter_pidfile_remove (pfh, 1));
}

/*
 * Written by Manuel Bouyer <bouyer@NetBSD.org>.
 * Public domain.
 */
#ifndef bswap32
	static uint32_t
	bswap32 (uint32_t x)
	{
		return ((x << 24) & 0xff000000) |
				((x << 8) & 0x00ff0000) |
				((x >> 8) & 0x0000ff00) |
				((x >> 24) & 0x000000ff);
	}
#endif

#ifndef bswap64
	static uint64_t
	bswap64 (uint64_t x)
	{
	#ifdef _LP64
		/*
		 * Assume we have wide enough registers to do it without touching
		 * memory.
		 */
		return ((x << 56) & 0xff00000000000000UL) |
				((x << 40) & 0x00ff000000000000UL) |
				((x << 24) & 0x0000ff0000000000UL) |
				((x << 8) & 0x000000ff00000000UL) |
				((x >> 8) & 0x00000000ff000000UL) |
				((x >> 24) & 0x0000000000ff0000UL) |
				((x >> 40) & 0x000000000000ff00UL) |
				((x >> 56) & 0x00000000000000ffUL);
	#else
		/*
		 * Split the operation in two 32bit steps.
		 */
		uint32_t tl, th;

		th = bswap32((uint32_t)(x & 0x00000000ffffffffULL));
		tl = bswap32((uint32_t)((x >> 32) & 0x00000000ffffffffULL));
		return ((uint64_t)th << 32) | tl;
	#endif
	}
#endif

static char *
rmilter_encode_base64_common (const u_char *in, size_t inlen, int str_len,
		size_t *outlen, int fold)
{
#define CHECK_SPLIT \
    do { if (str_len > 0 && cols >= str_len) { \
                *o++ = '\r'; \
                *o++ = '\n'; \
                if (fold) *o++ = '\t'; \
                cols = 0; \
    } } \
while (0)

	size_t allocated_len = (inlen / 3) * 4 + 5;
	char *out, *o;
	uint64_t n;
	uint32_t rem, t, carry;
	int cols, shift;
	static const char b64_enc[] =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
					"abcdefghijklmnopqrstuvwxyz"
					"0123456789+/";

	if (str_len > 0) {
		assert (str_len > 8);
		allocated_len += (allocated_len / str_len + 1) * (fold ? 3 : 2) + 1;
	}

	out = malloc (allocated_len);
	o = out;
	cols = 0;

	while (inlen > 6) {
		n = *(uint64_t *) in;
#if BYTE_ORDER == LITTLE_ENDIAN
		n = bswap64 (n);
#endif
		if (str_len <= 0 || cols <= str_len - 8) {
			*o++ = b64_enc[(n >> 58) & 0x3F];
			*o++ = b64_enc[(n >> 52) & 0x3F];
			*o++ = b64_enc[(n >> 46) & 0x3F];
			*o++ = b64_enc[(n >> 40) & 0x3F];
			*o++ = b64_enc[(n >> 34) & 0x3F];
			*o++ = b64_enc[(n >> 28) & 0x3F];
			*o++ = b64_enc[(n >> 22) & 0x3F];
			*o++ = b64_enc[(n >> 16) & 0x3F];
			cols += 8;
		}
		else {
			cols = str_len - cols;
			shift = 58;
			while (cols) {
				*o++ = b64_enc[(n >> shift) & 0x3F];
				shift -= 6;
				cols--;
			}

			*o++ = '\r';
			*o++ = '\n';
			if (fold) {
				*o++ = '\t';
			}

			/* Remaining bytes */
			while (shift >= 16) {
				*o++ = b64_enc[(n >> shift) & 0x3F];
				shift -= 6;
				cols++;
			}
		}

		in += 6;
		inlen -= 6;
	}

	CHECK_SPLIT;

	rem = 0;
	carry = 0;

	for (; ;) {
		/* Padding + remaining data (0 - 2 bytes) */
		switch (rem) {
		case 0:
			if (inlen-- == 0) {
				goto end;
			}
			t = *in++;
			*o++ = b64_enc[t >> 2];
			carry = (t << 4) & 0x30;
			rem = 1;
			cols++;
		case 1:
			if (inlen-- == 0) {
				goto end;
			}
			CHECK_SPLIT;
			t = *in++;
			*o++ = b64_enc[carry | (t >> 4)];
			carry = (t << 2) & 0x3C;
			rem = 2;
			cols++;
		default:
			if (inlen-- == 0) {
				goto end;
			}
			CHECK_SPLIT;
			t = *in++;
			*o++ = b64_enc[carry | (t >> 6)];
			cols++;
			CHECK_SPLIT;
			*o++ = b64_enc[t & 0x3F];
			cols++;
			CHECK_SPLIT;
			rem = 0;
		}
	}

	end:
	if (rem == 1) {
		*o++ = b64_enc[carry];
		cols++;
		CHECK_SPLIT;
		*o++ = '=';
		cols++;
		CHECK_SPLIT;
		*o++ = '=';
		cols++;
		CHECK_SPLIT;
	}
	else if (rem == 2) {
		*o++ = b64_enc[carry];
		cols++;
		CHECK_SPLIT;
		*o++ = '=';
		cols++;
	}

	CHECK_SPLIT;

	*o = '\0';

	if (outlen != NULL) {
		*outlen = o - out;
	}

	return out;
}

char *
rmilter_encode_base64 (const u_char *in, size_t inlen, int str_len,
		size_t *outlen)
{
	return rmilter_encode_base64_common (in, inlen, str_len, outlen, 0);
}

int
rmilter_connect_addr (const char *addr, int port, int msec)
{
	struct sockaddr_un su;
	int ofl, r;
	struct addrinfo hints, *res, *res0;
	int error;
	int s;
	const char *cause = NULL;
	char portbuf[32];
	socklen_t slen;

	if (addr[0] == '/' || addr[0] == '.') {
		/* Unix socket */
		su.sun_family = AF_UNIX;
		rmilter_strlcpy (su.sun_path, addr, sizeof (su.sun_path));
#if defined(FREEBSD) || defined(__APPLE__)
		su.sun_len = SUN_LEN (&su);
#endif
		s = socket (AF_UNIX, SOCK_STREAM, 0);
		if (s < 0) {
			cause = "socket";
			error = errno;
		}

		ofl = fcntl (s, F_GETFL, 0);
		fcntl (s, F_SETFL, ofl | O_NONBLOCK);
#ifdef SUN_LEN
		slen = SUN_LEN (&su);
#else
		slen = sizeof (su);
#endif

		if (connect (s, (struct sockaddr *)&su, slen) < 0) {
			if (errno != EINPROGRESS && errno != EAGAIN) {
				cause = "connect";
				error = errno;
				close (s);
				s = -1;
			}
		}
	}
	else {
		memset(&hints, 0, sizeof(hints));
		snprintf(portbuf, sizeof(portbuf), "%d", port);
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_NUMERICSERV;
		error = getaddrinfo (addr, portbuf, &hints, &res0);

		if (error) {
			msg_err ("rmilter_connect_addr: getaddrinfo failed for %s:%d: %s",
					addr, port, gai_strerror (error));
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
	}

	if (s < 0) {
		msg_err ("rmilter_connect_addr: connect failed: %s: %s",
				cause, strerror (error));
		return -1;
	}

	/* Get write readiness */
	if (rmilter_poll_fd (s, msec, POLL_OUT) == 1) {
		return s;
	}
	else {
		msg_err ("rmilter_connect_addr: connect failed: timeout");
		close (s);
	}

	return -1;
}

int
rmilter_poll_fd (int fd, int timeout, short events)
{
	int r;
	struct pollfd fds[1];

	fds->fd = fd;
	fds->events = events;
	fds->revents = 0;
	while ((r = poll (fds, 1, timeout)) < 0) {
		if (errno != EINTR)
			break;
	}


	return r;
}
