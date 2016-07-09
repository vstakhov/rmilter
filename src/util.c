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
#include "rmilter.h"
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
rmilter_connect_addr (const char *addr, int port, int msec,
		const struct mlfi_priv *priv)
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
			msg_err ("<%s>; rmilter_connect_addr: getaddrinfo failed for %s:%d: %s",
					priv->mlfi_id, addr, port, gai_strerror (error));
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
		msg_err ("<%s>; rmilter_connect_addr: connect failed: %s: %s",
				priv->mlfi_id, cause, strerror (error));
		return -1;
	}

	/* Get write readiness */
	if (rmilter_poll_fd (s, msec, POLLOUT) == 1) {
		return s;
	}
	else {
		msg_err ("<%s>; rmilter_connect_addr: connect failed: timeout", priv->mlfi_id);
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

static const unsigned char lc_map[256] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
		0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
		0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
		0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
		0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
		0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
		0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
		0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
		0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
		0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
		0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

void
rmilter_str_lc (char *str, unsigned int size)
{
	unsigned int leftover = size % 4;
	unsigned int fp, i;
	const uint8_t* s = (const uint8_t*) str;
	char *dest = str;
	unsigned char c1, c2, c3, c4;

	fp = size - leftover;

	for (i = 0; i != fp; i += 4) {
		c1 = s[i], c2 = s[i + 1], c3 = s[i + 2], c4 = s[i + 3];
		dest[0] = lc_map[c1];
		dest[1] = lc_map[c2];
		dest[2] = lc_map[c3];
		dest[3] = lc_map[c4];
		dest += 4;
	}

	switch (leftover) {
	case 3:
		*dest++ = lc_map[(unsigned char)str[i++]];
	case 2:
		*dest++ = lc_map[(unsigned char)str[i++]];
	case 1:
		*dest++ = lc_map[(unsigned char)str[i]];
	}

}

ssize_t
rmilter_atomic_write (int fd, const void *buf, size_t len)
{
	const char *s = buf;
	size_t pos = 0;
	ssize_t res;

	while (len > pos) {
		res = write (fd, s + pos, len - pos);

		switch (res) {
		case -1:
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}

			return -1;
		case 0:
			errno = EPIPE;
			return -1;
		default:
			pos += res;
		}
	}

	return pos;
}

int
rmilter_file_xopen (const char *fname, int oflags, unsigned int mode)
{
	struct stat sb;
	int fd;

	if (lstat (fname, &sb) == -1) {

		if (errno != ENOENT) {
			return (-1);
		}
	}
	else if (!S_ISREG (sb.st_mode)) {
		return -1;
	}

#ifdef HAVE_ONOFOLLOW
	fd = open (fname, oflags | O_NOFOLLOW, mode);
#else
	fd = open (fname, oflags, mode);
#endif

	return (fd);
}

void *
rmilter_file_xmap (const char *fname, unsigned int mode,
		size_t *size)
{
	int fd;
	struct stat sb;
	void *map;

	assert (fname != NULL);
	assert (size != NULL);

	if (mode & PROT_WRITE) {
		fd = rmilter_file_xopen (fname, O_RDWR, 0);
	}
	else {
		fd = rmilter_file_xopen (fname, O_RDONLY, 0);
	}

	if (fd == -1) {
		return NULL;
	}

	if (fstat (fd, &sb) == -1 || !S_ISREG (sb.st_mode)) {
		close (fd);

		return NULL;
	}

	map = mmap (NULL, sb.st_size, mode, MAP_SHARED, fd, 0);
	close (fd);

	if (map == MAP_FAILED) {
		return NULL;
	}

	*size = sb.st_size;

	return map;
}

GString *
rmilter_header_value_fold (const gchar *name,
		const gchar *value,
		guint fold_max)
{
	GString *res;
	const guint default_fold_max = 76;
	guint cur_len;
	const gchar *p, *c;
	gboolean first_token = TRUE;
	enum {
		fold_before = 0,
		fold_after
	} fold_type = fold_before;
	enum {
		read_token = 0,
		read_quoted,
		after_quote,
		fold_token,
	} state = read_token, next_state = read_token;

	g_assert (name != NULL);
	g_assert (value != NULL);

	/* Filter insane values */
	if (fold_max < 20) {
		fold_max = default_fold_max;
	}

	res = g_string_sized_new (strlen (value));

	c = value;
	p = c;
	/* name:<WSP> */
	cur_len = strlen (name) + 2;

	while (*p) {
		switch (state) {
		case read_token:
			if (*p == ',' || *p == ';') {
				/* We have something similar to the token's end, so check len */
				if (cur_len > fold_max * 0.8 && cur_len < fold_max) {
					/* We want fold */
					fold_type = fold_after;
					state = fold_token;
					next_state = read_token;
				}
				else if (cur_len > fold_max && !first_token) {
					fold_type = fold_before;
					state = fold_token;
					next_state = read_token;
				}
				else {
					g_string_append_len (res, c, p - c);
					c = p;
					first_token = FALSE;
				}
				p ++;
			}
			else if (*p == '"') {
				/* Fold before quoted tokens */
				g_string_append_len (res, c, p - c);
				c = p;
				state = read_quoted;
			}
			else if (*p == '\r') {
				/* Reset line length */
				cur_len = 0;

				while (g_ascii_isspace (*p)) {
					p ++;
				}

				g_string_append_len (res, c, p - c);
				c = p;
			}
			else if (g_ascii_isspace (*p)) {
				if (cur_len > fold_max * 0.8 && cur_len < fold_max) {
					/* We want fold */
					fold_type = fold_after;
					state = fold_token;
					next_state = read_token;
				}
				else if (cur_len > fold_max && !first_token) {
					fold_type = fold_before;
					state = fold_token;
					next_state = read_token;
				}
				else {
					g_string_append_len (res, c, p - c);
					c = p;
					first_token = FALSE;
					p ++;
				}
			}
			else {
				p ++;
				cur_len ++;
			}
			break;
		case fold_token:
			/* Here, we have token start at 'c' and token end at 'p' */
			if (fold_type == fold_after) {
				g_string_append_len (res, c, p - c);
				g_string_append_len (res, "\r\n\t", 3);

				/* Skip space if needed */
				if (g_ascii_isspace (*p)) {
					p ++;
				}
			}
			else {
				/* Skip space if needed */
				if (g_ascii_isspace (*c)) {
					c ++;
				}

				g_string_append_len (res, "\r\n\t", 3);
				g_string_append_len (res, c, p - c);
			}

			c = p;
			state = next_state;
			cur_len = 0;
			first_token = TRUE;
			break;

		case read_quoted:
			if (p != c && *p == '"') {
				state = after_quote;
			}
			p ++;
			cur_len ++;
			break;

		case after_quote:
			state = read_token;
			/* Skip one more character after the quote */
			p ++;
			cur_len ++;
			g_string_append_len (res, c, p - c);
			c = p;
			first_token = TRUE;
			break;
		}
	}

	/* Last token */
	switch (state) {
	case read_token:
		if (cur_len > fold_max && !first_token) {
			g_string_append_len (res, "\r\n\t", 3);
			g_string_append_len (res, c, p - c);
		}
		else {
			g_string_append_len (res, c, p - c);
		}
		break;
	case read_quoted:
	case after_quote:
		g_string_append_len (res, c, p - c);
		break;

	default:
		g_assert (p == c);
		break;
	}

	return res;
}
