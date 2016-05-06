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

#ifndef UTIL_H_
#define UTIL_H_

#include "config.h"

struct rmilter_inet_address {
	int family;
	union {
		struct sockaddr_in sa4;
		struct sockaddr_in6 sa6;
		struct sockaddr sa;
	} addr;
};

/**
 * Copy src to dest limited to len, in compare with standard strlcpy(3) rmilter_strlcpy does not
 * traverse the whole string and it is possible to use it for non NULL terminated strings. This is
 * more like memccpy(dst, src, size, '\0')
 *
 * @param dst destination string
 * @param src source string
 * @param siz length of destination buffer
 * @return bytes copied
 */
size_t rmilter_strlcpy (char *dst, const char *src, size_t siz);

typedef struct rmilter_pidfh_s {
	int pf_fd;
#ifdef HAVE_PATH_MAX
	char pf_path[PATH_MAX + 1];
#elif defined(HAVE_MAXPATHLEN)
	char pf_path[MAXPATHLEN + 1];
#else
	char pf_path[1024 + 1];
#endif
	dev_t pf_dev;
	ino_t pf_ino;
} rmilter_pidfh_t;
rmilter_pidfh_t * rmilter_pidfile_open (const char *path,
	mode_t mode,
	pid_t *pidptr);
int rmilter_pidfile_write (rmilter_pidfh_t *pfh);
int rmilter_pidfile_close (rmilter_pidfh_t *pfh);
int rmilter_pidfile_remove (rmilter_pidfh_t *pfh);

#define msg_err(args...) syslog(LOG_ERR, ##args)
#define msg_warn(args...)	syslog(LOG_WARNING, ##args)
#define msg_info(args...)	syslog(LOG_INFO, ##args)
#ifdef WITH_DEBUG
#define msg_debug(args...) syslog(LOG_DEBUG, ##args)
#else
#define msg_debug(args...) do {} while(0)
#endif

struct mlfi_priv;

char* rmilter_encode_base64 (const u_char *in, size_t inlen, int str_len,
		size_t *outlen);

int rmilter_connect_addr (const char *addr, int port, int msec, struct mlfi_priv *priv);
int rmilter_poll_fd (int fd, int timeout, short events);

#define msec_to_tv(msec, tv) do { (tv)->tv_sec = (msec) / 1000; (tv)->tv_usec = \
		((msec) - (tv)->tv_sec * 1000) * 1000; \
} while (0)

void rmilter_str_lc (char *str, unsigned int size);

#endif /* UTIL_H_ */
