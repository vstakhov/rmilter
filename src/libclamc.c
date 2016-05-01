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

/******************************************************************************

 Clamav clamd client library

 Scanning file with tcp-based clamd servers. Library for general use.
 Thread-safe if compiled with _THREAD_SAFE defined.

 Warnings logged via syslog (must be opended).

 Random generator used (random() must be initialized before use, e.g.
 by srandomdev() call).

 Written by Maxim Dounin, mdounin@rambler-co.ru

 $Id$

 ******************************************************************************/

#include "config.h"

#include "cfg_file.h"
#include "rmilter.h"
#include "libclamc.h"
#include "sds.h"

/* Maximum time in seconds during which clamav server is marked inactive after scan error */
#define INACTIVE_INTERVAL 60.0
/* Maximum number of failed attempts before marking server as inactive */
#define MAX_FAILED 5
/* Maximum inactive timeout (20 min) */
#define MAX_TIMEOUT 1200.0

/* Global mutexes */

#ifdef _THREAD_SAFE
pthread_mutex_t mx_clamav_write = PTHREAD_MUTEX_INITIALIZER;
#endif

/*****************************************************************************/

/*
 * clamscan_socket() - send file to specified host. See clamscan() for
 * load-balanced wrapper.
 *
 * returns 0 when checked, -1 on some error during scan (try another server), -2
 * on unexpected error (probably clamd died on our file, fallback to another
 * host not recommended)
 */

static int clamscan_socket(const char *file, const struct clamav_server *srv,
		char *strres, size_t strres_len, struct config_file *cfg,
		struct mlfi_priv *priv)
{
	char *c;
	sds readbuf;
	char buf[2048];
	struct sockaddr_un server_un;
	struct sockaddr_in server_in, server_w;
	int s, r, fd, port = 0, ofl;
	uint32_t sz;
	size_t size;
	struct stat sb;

	*strres = '\0';

	/* somebody doesn't need reply... */
	if (!srv)
		return 0;

	s = rmilter_connect_addr (srv->name, srv->port, cfg->clamav_connect_timeout);

	if (s == -1) {
		return -1;
	}

	fd = open (file, O_RDONLY);

	if (fstat (fd, &sb) == -1) {
		msg_warn("<%s>; clamav: stat failed for %s: %s", priv->mlfi_id,
				file, strerror (errno));
		close (s);
		return -1;
	}

	sz = sb.st_size;
	sz = htonl (sz);
	r = rmilter_strlcpy (buf, "nINSTREAM\n", sizeof (buf) - sizeof (sz));
	memcpy (&buf[r], &sz, sizeof (sz));
	r += sizeof (sz);

	if (write (s, buf, r) != r) {
		msg_warn("<%s>; clamav: write %s: %s", priv->mlfi_id,
				srv->name, strerror (errno));
		close (s);
		return -1;
	}

	/*
	 * send data stream
	 */
	/* Set blocking again */
	ofl = fcntl (s, F_GETFL, 0);
	fcntl (s, F_SETFL, ofl & (~O_NONBLOCK));

#ifdef HAVE_SENDFILE
#if defined(FREEBSD)
	if (sendfile(fd, s, 0, 0, 0, 0, 0) != 0) {
		msg_warn("<%s>; clamav: sendfile %s (%s): %s", priv->mlfi_id,
				file, srv->name, strerror (errno));
		close(fd);
		close(s);
		return -1;
	}
#elif defined(LINUX)
	off_t off = 0;
	if (sendfile(s, fd, &off, sb.st_size) == -1) {
		msg_warn("<%s>; clamav: sendfile %s (%s): %s", priv->mlfi_id,
				file, srv->name, strerror (errno));
		close(fd);
		close(s);
		return -1;
	}
#else
	while ((r = read (fd, buf, sizeof(buf))) > 0) {
		if (write (s, buf, r) <= 0) {
			msg_warn("<%s>; clamav: write (%s): %s", priv->mlfi_id,
					srv->name, strerror (errno));
			close(fd);
			close(s);
			return -1;
		}
	}
#endif
#endif
	close (fd);

	/* Send zero chunk */
	sz = 0;
	if (write (s, &sz, sizeof (sz)) <= 0) {
		msg_warn("<%s>; clamav: write (%s): %s", priv->mlfi_id,
				srv->name, strerror (errno));
		close(fd);
		close(s);
		return -1;
	}

	fcntl (s, F_SETFL, ofl | O_NONBLOCK);

	/* wait for reply */
	if (rmilter_poll_fd (s, cfg->clamav_results_timeout, POLLIN) < 1) {
		msg_warn("<%s>; clamav: timeout waiting results %s", priv->mlfi_id,
				srv->name);
		close (s);
		return -1;
	}

	/*
	 * read results
	 */
	readbuf = sdsempty();

	for (;;) {
		if (rmilter_poll_fd (s, cfg->spamd_results_timeout, POLLIN) < 1) {
			msg_warn("<%s>; clamav: timeout waiting results %s", priv->mlfi_id,
					srv->name);
			close (s);
			return -1;
		}

		r = read (s, buf, sizeof (buf));

		if (r == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				continue;
			}
			else {
				msg_warn("<%s>; clamav: read, %s, %s", priv->mlfi_id,
						srv->name, strerror (errno));
				close (s);
				return -1;
			}
		}
		else if (r == 0) {
			break;
		}
		else {
			readbuf = sdscatlen (readbuf, buf, r);
		}
	}

	size = sdslen (readbuf);

	close (s);

	/*
	 * ok, we got result; test what we got
	 */

	/* msg_warn("clamav: %s", buf); */
	if ((c = strstr (readbuf, "OK\n")) != NULL) {
		/* <file> ": OK\n" */
		sdsfree (readbuf);
		return 0;

	}
	else if ((c = strstr (readbuf, "FOUND\n")) != NULL) {
		/* <file> ": " <virusname> " FOUND\n" */

		if (strncmp (readbuf, "stream", sizeof ("stream") - 1) != 0) {
			msg_warn ("<%s>; clamav: paths differ: '%s' instead of 'stream'",
					priv->mlfi_id, readbuf);
			snprintf (strres, strres_len, "%.*s", (int)(c - readbuf), readbuf);
		}
		else {
			*(--c) = 0;
			c = readbuf + sizeof ("stream") + 1;
			snprintf (strres, strres_len, "%s", c);
		}

		sdsfree (readbuf);

		return 0;

	}
	else if ((c = strstr (readbuf, "ERROR\n")) != NULL) {
		*(--c) = 0;
		msg_warn("<%s>; clamav: error (%s) %s", priv->mlfi_id, srv->name, readbuf);
		sdsfree (readbuf);
		return -1;
	}

	/*
	 * Most common reason is clamd died while processing our request. Try to
	 * save file for further investigation and fail.
	 */
	sdsfree (readbuf);
	msg_warn("<%s>; clamav: unexpected result on file (%s) %s, %s",
			priv->mlfi_id, srv->name, file,
			buf);

	return -2;
}

/*
 * clamscan() - send file to one of remote clamd, with pseudo load-balancing
 * (select one random server, fallback to others in case of errors).
 *
 * returns 0 if file scanned (or not scanned due to filesize limit), -1 when
 * retry limit exceeded, -2 on unexpected error, e.g. unexpected reply from
 * server (suppose scanned message killed clamd...)
 */

int clamscan (void *ctx, struct mlfi_priv *priv, struct config_file *cfg,
		char *strres, size_t strres_len)
{
	int retry = 5, r = -2;
	/* struct stat sb; */
	struct timeval t;
	double ts, tf;
	struct clamav_server *selected = NULL;
	struct timespec sleep_ts;
	const char *file = priv->file;

	*strres = '\0';
	/*
	 * Parse sockets to use in balancing.
	 */
	/* msg_warn("(clamscan) defined %d server sockets...", sockets_n); */

	/*
	 * save scanning start time
	 */
	gettimeofday (&t, NULL);
	ts = t.tv_sec + t.tv_usec / 1000000.0;
	retry = cfg->spamd_retry_count;
	sleep_ts.tv_sec = cfg->spamd_retry_timeout / 1000;
	sleep_ts.tv_nsec = (cfg->spamd_retry_timeout % 1000) * 1000000ULL;

	/* try to scan with available servers */
	while (1) {
		if (cfg->weighted_clamav) {
			selected = (struct clamav_server *) get_upstream_master_slave (
					(void *) cfg->clamav_servers, cfg->clamav_servers_num,
					sizeof(struct clamav_server), t.tv_sec,
					cfg->clamav_error_time, cfg->clamav_dead_time,
					cfg->clamav_maxerrors);
		}
		else {
			selected = (struct clamav_server *) get_random_upstream (
					(void *) cfg->clamav_servers, cfg->clamav_servers_num,
					sizeof(struct clamav_server), t.tv_sec,
					cfg->clamav_error_time, cfg->clamav_dead_time,
					cfg->clamav_maxerrors);
		}
		if (selected == NULL) {
			msg_err("<%s>; clamscan: upstream get error, %s", priv->mlfi_id,
					file);
			return -1;
		}

		msg_info ("<%s>; clamscan: start scanning message on %s", priv->mlfi_id,
						selected->name);
		r = clamscan_socket (file, selected, strres, strres_len, cfg, priv);
		msg_info ("<%s>; clamscan: finish scanning message on %s", priv->mlfi_id,
						selected->name);

		if (r == 0) {
			upstream_ok (&selected->up, t.tv_sec);
			break;
		}
		upstream_fail (&selected->up, t.tv_sec);
		if (r == -2) {
			msg_warn("<%s>; clamscan: unexpected problem, %s, %s", priv->mlfi_id,
					selected->name,
					file);
			break;
		}
		if (--retry < 1) {
			msg_warn("<%s>; clamscan: retry limit exceeded, %s, %s",
					priv->mlfi_id, selected->name,
					file);
			break;
		}
		msg_warn("<%s>; clamscan: failed to scan, retry, %s, %s", priv->mlfi_id,
				selected->name,
				file);
		nanosleep (&sleep_ts, NULL);
	}

	/*
	 * print scanning time, server and result
	 */
	gettimeofday (&t, NULL);
	tf = t.tv_sec + t.tv_usec / 1000000.0;

	if (*strres) {
		msg_info("<%s>; clamscan: scan %f, %s, found %s, %s", priv->mlfi_id,
				tf - ts, selected->name,
				strres, file);
	}
	else {
		msg_info("<%s>; clamscan: scan %f, %s, %s", priv->mlfi_id,
				tf - ts, selected->name, file);
	}

	return r;
}
