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

#include "utlist.h"
#include "cfg_file.h"
#include "rmilter.h"
#include "libspamd.h"
#include "mfapi.h"
#include "sds.h"

/* Maximum time in seconds during which spamd server is marked inactive after scan error */
#define INACTIVE_INTERVAL 60.0
/* Maximum number of failed attempts before marking server as inactive */
#define MAX_FAILED 5
/* Maximum inactive timeout (20 min) */
#define MAX_TIMEOUT 1200.0

/* Global mutexes */

#ifdef _THREAD_SAFE
pthread_mutex_t mx_spamd_write = PTHREAD_MUTEX_INITIALIZER;
#endif

/*
 * rspamdscan_socket() - send file to specified host. See spamdscan() for
 * load-balanced wrapper.
 *
 * returns 0 when spam not found, 1 when spam found, -1 on some error during scan (try another server), -2
 * on unexpected error (probably clamd died on our file, fallback to another
 * host not recommended)
 */

static int rspamdscan_socket(SMFICTX *ctx, struct mlfi_priv *priv,
		const struct spamd_server *srv, struct config_file *cfg,
		rspamd_result_t *res, char **mid)
{
	char buf[8192];
	sds readbuf;
	char *c, *p, *err_str;
	struct sockaddr_un server_un;
	struct sockaddr_in server_in;
	int s, r, fd, ofl, size = 0, to_write, written, state, next_state, toklen;
	int remain;
	struct stat sb;
	struct rspamd_metric_result *cur = NULL;
	struct rcpt *rcpt;
	struct rspamd_symbol *cur_symbol;

	/* somebody doesn't need reply... */
	if (!srv)
		return 0;

	s = rmilter_connect_addr (srv->name, srv->port, cfg->spamd_connect_timeout);

	/* Get file size */
	fd = open (priv->file, O_RDONLY);
	if (fstat (fd, &sb) == -1) {
		msg_warn("<%s> rspamd: stat failed: %s",  priv->mlfi_id, strerror (errno));
		close (s);
		return -1;
	}

	if (rmilter_poll_fd (s, cfg->spamd_connect_timeout, POLLOUT) < 1) {
		msg_warn("<%s> rspamd: timeout waiting writing, %s",  priv->mlfi_id, srv->name);
		close (s);
		return -1;
	}
	/* Set blocking again */
	ofl = fcntl (s, F_GETFL, 0);
	fcntl (s, F_SETFL, ofl & (~O_NONBLOCK));

	r = 0;
	to_write = sizeof(buf) - r;
	written = snprintf(buf + r, to_write,
			"SYMBOLS RSPAMC/1.2\r\nContent-length: %ld\r\n",
			(long int )sb.st_size);
	if (written > to_write) {
		msg_warn("<%s> rspamd: buffer overflow while filling buffer (%s)",
				 priv->mlfi_id, srv->name);
		close (fd);
		close (s);
		return -1;
	}
	r += written;

	DL_FOREACH (priv->rcpts, rcpt)
	{
		to_write = sizeof(buf) - r;
		written = snprintf(buf + r, to_write, "Rcpt: %s\r\n", rcpt->r_addr);
		if (written > to_write) {
			msg_warn("<%s> rspamd: buffer overflow while filling buffer (%s)",
					 priv->mlfi_id, srv->name);
			close (fd);
			close (s);
			return -1;
		}
		r += written;
	}

	if (priv->priv_from[0] != '\0') {
		to_write = sizeof(buf) - r;
		written = snprintf(buf + r, to_write, "From: %s\r\n", priv->priv_from);
		if (written > to_write) {
			msg_warn("<%s> rspamd: buffer overflow while filling buffer (%s)",
					 priv->mlfi_id, srv->name);
			close (fd);
			close (s);
			return -1;
		}
		r += written;
	}
	if (priv->priv_helo[0] != '\0') {
		to_write = sizeof(buf) - r;
		written = snprintf(buf + r, to_write, "Helo: %s\r\n", priv->priv_helo);
		if (written > to_write) {
			msg_warn("<%s> rspamd: buffer overflow while filling buffer (%s)",
					 priv->mlfi_id, srv->name);
			close (fd);
			close (s);
			return -1;
		}
		r += written;
	}
	if (priv->priv_hostname[0] != '\0'
			&& memcmp (priv->priv_hostname, "unknown", 8) != 0) {
		to_write = sizeof(buf) - r;
		written = snprintf(buf + r, to_write, "Hostname: %s\r\n",
				priv->priv_hostname);
		if (written > to_write) {
			msg_warn("<%s> rspamd: buffer overflow while filling buffer (%s)",
					 priv->mlfi_id, srv->name);
			close (fd);
			close (s);
			return -1;
		}
		r += written;
	}
	if (priv->priv_ip[0] != '\0') {
		to_write = sizeof(buf) - r;
		written = snprintf(buf + r, to_write, "IP: %s\r\n", priv->priv_ip);
		if (written > to_write) {
			msg_warn("<%s> rspamd: buffer overflow while filling buffer (%s)",
					 priv->mlfi_id, srv->name);
			close (fd);
			close (s);
			return -1;
		}
		r += written;
	}
	if (priv->priv_user[0] != '\0') {
		to_write = sizeof(buf) - r;
		written = snprintf(buf + r, to_write, "User: %s\r\n", priv->priv_user);
		if (written > to_write) {
			msg_warn("<%s> rspamd: buffer overflow while filling buffer (%s)",
					 priv->mlfi_id, srv->name);
			close (fd);
			close (s);
			return -1;
		}
		r += written;
	}
	to_write = sizeof(buf) - r;
	written = snprintf(buf + r, to_write, "Queue-ID: %s\r\n\r\n",
			priv->mlfi_id);
	if (written > to_write) {
		msg_warn("<%s> rspamd: buffer overflow while filling buffer (%s)",
				 priv->mlfi_id, srv->name);
		close (fd);
		close (s);
		return -1;
	}
	r += written;

	if (write (s, buf, r) == -1) {
		msg_warn("<%s> rspamd: write (%s), %s", priv->mlfi_id, srv->name, strerror (errno));
		close (fd);
		close (s);
		return -1;
	}

#ifdef HAVE_SENDFILE
#if defined(FREEBSD)
	if (sendfile(fd, s, 0, 0, 0, 0, 0) != 0) {
		msg_warn("<%s> rspamd: sendfile (%s), %s", priv->mlfi_id, srv->name, strerror (errno));
		close(fd);
		close(s);
		return -1;
	}
#elif defined(LINUX)
	off_t off = 0;
	if (sendfile(s, fd, &off, sb.st_size) == -1) {
		msg_warn("<%s> rspamd: sendfile (%s), %s", priv->mlfi_id, srv->name, strerror (errno));
		close(fd);
		close(s);
		return -1;
	}
#else
	while ((r = read (fd, buf, sizeof (buf))) > 0) {
		write (s, buf, r);
	}
#endif
#endif

	fcntl (s, F_SETFL, ofl|O_NONBLOCK);
	close (fd);

	/*
	 * read results
	 */
	readbuf = sdsempty ();

	for (;;) {
		if (rmilter_poll_fd (s, cfg->spamd_results_timeout, POLLIN) < 1) {
			msg_warn("<%s> rspamd: timeout waiting results %s", priv->mlfi_id,
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
				msg_warn("<%s> rspamd: read, %s, %s", priv->mlfi_id,  srv->name,
						strerror (errno));
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

#define TEST_WORD(x)																\
do {																				\
	if (remain < sizeof ((x)) - 1 || memcmp (p, (x), sizeof ((x)) - 1) != 0) {		\
		msg_warn ("<%s> invalid reply from server %s at state %d, expected: %s, got %*s", priv->mlfi_id, srv->name, state, ((x)), (int)sizeof((x)), p);				\
		return -1;																	\
	}																				\
	p += sizeof((x)) - 1;															\
	remain -= sizeof((x)) - 1;														\
} while (0)

	c = readbuf;
	p = readbuf;
	remain = size - 1;
	state = 0;
	next_state = 100;

	while (remain > 0) {
		switch (state) {
		case 0:
			/*
			 * Expect first reply line:
			 * RSPAMD/{VERSION} {ERROR_CODE} {DESCR} CRLF
			 */
			TEST_WORD("RSPAMD/");
			if ((c = strchr (p, ' ')) == NULL) {
				msg_warn("<%s> invalid reply from server %s on state %d",
						priv->mlfi_id, srv->name,
						state);
				sdsfree (readbuf);
				return -1;
			}
			/* Well now in c we have space symbol, skip all */
			while (remain > 0 && isspace (*c)) {
				c++;
			}
			/* Now check code */
			if (*c != '0') {
				msg_warn("<%s> invalid reply from server %s on state %d, code: %c",
						 priv->mlfi_id, srv->name, state, *c);
				sdsfree (readbuf);
				return -1;
			}
			/* Now skip everything till \n */
			if ((c = strchr (c, '\n')) == NULL) {
				msg_warn("<%s> invalid reply from server %s on state %d",
						priv->mlfi_id, srv->name,
						state);
				sdsfree (readbuf);
				return -1;
			}
			c++;
			remain -= c - p;
			p = c;
			next_state = 2;
			state = 99;
			break;
		case 2:
			/*
			 * In this state we compare begin of line with Metric:
			 */
			TEST_WORD("Metric:");
			cur = malloc (sizeof(struct rspamd_metric_result));
			if (cur == NULL) {
				msg_err("<%s> malloc failed: %s", priv->mlfi_id, strerror (errno));
				sdsfree (readbuf);
				return -1;
			}
			cur->subject = NULL;
			TAILQ_INIT(&cur->symbols);
			next_state = 3;
			state = 99;
			break;
		case 3:
			/*
			 * In this state we parse metric line
			 * Typical line looks as name; result; score1 / score2[ / score3] and we are interested in:
			 * name, result, score1 and score2
			 */
			if ((c = strchr (p, ';')) == NULL) {
				msg_warn(
						"<%s> invalid reply from server %s on state %d, at position: %s",
						 priv->mlfi_id, srv->name, state, p);
				sdsfree (readbuf);
				return -1;
			}
			/* Now in c we have end of name and in p - begin of name, so copy this data to temp buffer */
			cur->metric_name = malloc (c - p + 1);
			if (cur->metric_name == NULL) {
				msg_err("<%s> malloc failed: %s",  priv->mlfi_id, strerror (errno));
				sdsfree (readbuf);
				return -1;
			}
			rmilter_strlcpy (cur->metric_name, p, c - p + 1);
			remain -= c - p + 1;
			p = c + 1;
			/* Now skip result from rspamd, just extract 2 numbers */
			if ((c = strchr (p, ';')) == NULL) {
				msg_warn(
						"<%s> invalid reply from server %s on state %d, at position: %s",
						 priv->mlfi_id, srv->name, state, p);
				sdsfree (readbuf);
				return -1;
			}
			remain -= c - p + 1;
			p = c + 1;
			/* Now skip spaces */
			while (isspace (*p) && remain > 0) {
				p++;
				remain--;
			}
			/* Try to read first mark */
			cur->score = strtod (p, &err_str);
			if (err_str != NULL && (*err_str != ' ' && *err_str != '/')) {
				msg_warn(
						"<%s> invalid reply from server %s on state %d, error converting score number: %s",
						 priv->mlfi_id, srv->name, state, err_str);
				sdsfree (readbuf);
				return -1;
			}
			remain -= err_str - p;
			p = err_str;
			while (remain > 0 && (*p == ' ' || *p == '/')) {
				remain--;
				p++;
			}
			/* Try to read second mark */
			cur->required_score = strtod (p, &err_str);
			if (err_str != NULL
					&& (*err_str != ' ' && *err_str != '/' && *err_str != '\r')) {
				msg_warn(
						"<%s> invalid reply from server %s on state %d, error converting required score number: %s",
						 priv->mlfi_id, srv->name, state, err_str);
				sdsfree (readbuf);
				return -1;
			}
			remain -= err_str - p;
			p = err_str;
			while (remain > 0 && *p != '\n') {
				remain--;
				p++;
			}
			state = 99;
			next_state = 4;
			break;
		case 4:
			/* Symbol/Action */
			if (remain >= sizeof("Symbol:")
					&& memcmp (p, "Symbol:", sizeof("Symbol:") - 1) == 0) {
				state = 99;
				next_state = 5;
				p += sizeof("Symbol:") - 1;
				remain -= sizeof("Symbol:") - 1;
			}
			else if (remain >= sizeof("Action:")
					&& memcmp (p, "Action:", sizeof("Action:") - 1) == 0) {
				state = 99;
				next_state = 6;
				p += sizeof("Action:") - 1;
				remain -= sizeof("Action:") - 1;
			}
			else if (remain >= sizeof("Metric:")
					&& memcmp (p, "Metric:", sizeof("Metric:") - 1) == 0) {
				state = 99;
				next_state = 3;
				p += sizeof("Metric:") - 1;
				remain -= sizeof("Metric:") - 1;
				TAILQ_INSERT_HEAD(res, cur, entry);
				cur = malloc (sizeof(struct rspamd_metric_result));
				if (cur == NULL) {
					msg_err("<%s> malloc failed: %s", priv->mlfi_id, strerror (errno));
					sdsfree (readbuf);
					return -1;
				}
				TAILQ_INIT(&cur->symbols);
			}
			else if (remain >= sizeof("Message-ID:")
					&& memcmp (p, "Message-ID:", sizeof("Message-ID:") - 1)
							== 0) {
				state = 99;
				next_state = 7;
				p += sizeof("Message-ID:") - 1;
				remain -= sizeof("Message-ID:") - 1;
			}
			else if (remain >= sizeof("Subject:")
					&& memcmp (p, "Subject:", sizeof("Subject:") - 1) == 0) {
				state = 99;
				next_state = 8;
				p += sizeof("Subject:") - 1;
				remain -= sizeof("Subject:") - 1;
			}
			else {
				toklen = strcspn (p, "\r\n");
				if (toklen > remain) {
					msg_info("bad symbol name detected");
					sdsfree (readbuf);
					return -1;
				}
				remain -= toklen;
				p += toklen;
				next_state = 4;
				state = 99;
			}
			break;
		case 5:
			/* Parse symbol line */
			toklen = strcspn (p, ";\r\n");
			if (toklen == 0 || toklen > remain) {
				/* Bad symbol name */
				msg_info("<%s> bad symbol name detected", priv->mlfi_id);
				sdsfree (readbuf);
				return -1;
			}
			cur_symbol = malloc (sizeof(struct rspamd_symbol));
			if (cur_symbol == NULL) {
				msg_err("malloc failed: %s", strerror (errno));
				sdsfree (readbuf);
				return -1;
			}
			cur_symbol->symbol = malloc (toklen + 1);
			if (cur_symbol->symbol == NULL) {
				msg_err("malloc failed: %s", strerror (errno));
				sdsfree (readbuf);
				return -1;
			}
			rmilter_strlcpy (cur_symbol->symbol, p, toklen + 1);
			TAILQ_INSERT_HEAD(&cur->symbols, cur_symbol, entry);
			/* Skip to the end of line */
			toklen = strcspn (p, "\r\n");
			if (toklen > remain) {
				msg_info("bad symbol name detected");
				sdsfree (readbuf);
				return -1;
			}
			remain -= toklen;
			p += toklen;
			next_state = 4;
			state = 99;
			break;
		case 6:
			/* Parse action */
			if (memcmp (p, "reject", sizeof("reject") - 1) == 0) {
				cur->action = METRIC_ACTION_REJECT;
			}
			else if (memcmp (p, "greylist", sizeof("greylist") - 1) == 0) {
				cur->action = METRIC_ACTION_GREYLIST;
			}
			else if (memcmp (p, "add header", sizeof("add header") - 1) == 0) {
				cur->action = METRIC_ACTION_ADD_HEADER;
			}
			else if (memcmp (p, "rewrite subject",
					sizeof("rewrite subject") - 1) == 0) {
				cur->action = METRIC_ACTION_REWRITE_SUBJECT;
			}
			else {
				cur->action = METRIC_ACTION_NOACTION;
			}
			/* Skip to the end of line */
			toklen = strcspn (p, "\r\n");
			if (toklen > remain) {
				msg_info("bad symbol name detected");
				sdsfree (readbuf);
				return -1;
			}
			remain -= toklen;
			p += toklen;
			next_state = 4;
			state = 99;
			break;
		case 7:
			/* Parse message id */
			toklen = strcspn (p, "\r\n");
			*mid = malloc (toklen + 1);
			rmilter_strlcpy (*mid, p, toklen + 1);
			remain -= toklen;
			p += toklen;
			next_state = 4;
			state = 99;
			break;
		case 8:
			/* Parse subject line */
			toklen = strcspn (p, "\r\n");
			if (cur) {
				cur->subject = malloc (toklen + 1);
				rmilter_strlcpy (cur->subject, p, toklen + 1);
			}
			remain -= toklen;
			p += toklen;
			next_state = 4;
			state = 99;
			break;
		case 99:
			/* Skip spaces */
			if (isspace (*p)) {
				p++;
				remain--;
			}
			else {
				state = next_state;
			}
			break;
		default:
			msg_err("<%s> state machine breakage detected, state = %d, p = %s",
					 priv->mlfi_id, state, p);
			sdsfree (readbuf);
			return -1;
		}
	}

	if (cur != NULL) {
		TAILQ_INSERT_HEAD(res, cur, entry);
	}
	sdsfree (readbuf);

	return 0;
}
#undef TEST_WORD
/*
 * spamdscan() - send file to one of remote spamd, with pseudo load-balancing
 * (select one random server, fallback to others in case of errors).
 *
 * returns 0 if file scanned and spam not found,
 * 1 if file scanned and spam found ,
 * 2 if file scanned and this is probably spam,
 * -1 when retry limit exceeded, -2 on unexpected error, e.g. unexpected reply from
 * server (suppose scanned message killed spamd...)
 */

int spamdscan(void *_ctx, struct mlfi_priv *priv, struct config_file *cfg,
		char **subject, int extra)
{
	int retry, r = -2, hr = 0, to_trace = 0, i, j;
	struct timeval t;
	double ts, tf;
	struct spamd_server *selected = NULL;
	char rbuf[1024], hdrbuf[1024], bar_buf[128];
	char *prefix = "s", *mid = NULL, *c;
	rspamd_result_t res;
	struct rspamd_metric_result *cur = NULL, *tmp;
	struct rspamd_symbol *cur_symbol, *tmp_symbol;
	enum rspamd_metric_action res_action = METRIC_ACTION_NOACTION;
	struct timespec sleep_ts;
	SMFICTX *ctx = _ctx;

	gettimeofday (&t, NULL);
	ts = t.tv_sec + t.tv_usec / 1000000.0;
	retry = cfg->spamd_retry_count;
	sleep_ts.tv_sec = cfg->spamd_retry_timeout / 1000;
	sleep_ts.tv_nsec = (cfg->spamd_retry_timeout % 1000) * 1000000ULL;

	TAILQ_INIT(&res);

	/* try to scan with available servers */
	while (1) {
		if (extra) {
			selected = (struct spamd_server *) get_random_upstream (
					(void *) cfg->extra_spamd_servers,
					cfg->extra_spamd_servers_num, sizeof(struct spamd_server),
					t.tv_sec, cfg->spamd_error_time, cfg->spamd_dead_time,
					cfg->spamd_maxerrors);
		}
		else {
			selected = (struct spamd_server *) get_random_upstream (
					(void *) cfg->spamd_servers, cfg->spamd_servers_num,
					sizeof(struct spamd_server), t.tv_sec,
					cfg->spamd_error_time, cfg->spamd_dead_time,
					cfg->spamd_maxerrors);
		}
		if (selected == NULL) {
			msg_err("<%s> spamdscan: upstream get error, %s", priv->mlfi_id,
					priv->file);
			return -1;
		}

		msg_info ("<%s> spamdscan: start scanning message on %s", priv->mlfi_id,
				selected->name);

		prefix = "rs";
		r = rspamdscan_socket (ctx, priv, selected, cfg, &res, &mid);

		msg_info ("<%s> spamdscan: finish scanning message on %s", priv->mlfi_id,
						selected->name);

		if (r == 0 || r == 1) {
			upstream_ok (&selected->up, t.tv_sec);
			break;
		}
		upstream_fail (&selected->up, t.tv_sec);
		if (r == -2) {
			msg_warn("<%s> %spamdscan: unexpected problem, %s, %s",
					priv->mlfi_id, prefix,
					selected->name, priv->file);
			break;
		}
		if (--retry < 1) {
			msg_warn("<%s> %spamdscan: retry limit exceeded, %s, %s",
					priv->mlfi_id, prefix,
					selected->name, priv->file);
			break;
		}

		msg_warn("<%s> %spamdscan: failed to scan, retry, %s, %s",
				priv->mlfi_id, prefix,
				selected->name, priv->file);
		nanosleep (&sleep_ts, NULL);
	}

	/*
	 * print scanning time, server and result
	 */
	gettimeofday (&t, NULL);
	tf = t.tv_sec + t.tv_usec / 1000000.0;

	/* Parse res tailq */
	cur = TAILQ_FIRST(&res);
	while (cur) {
		if (cur->metric_name) {
			if (cfg->extended_spam_headers && !priv->authenticated) {
				hr = snprintf(hdrbuf, sizeof(hdrbuf), "%s: %s [%.2f / %.2f]%c",
						cur->metric_name,
						cur->score > cur->required_score ? "True" : "False",
						cur->score, cur->required_score,
						TAILQ_FIRST(&cur->symbols) != NULL ? '\n' : ' ');
			}
			r =
					snprintf(rbuf, sizeof(rbuf),
							"spamdscan: scan qid: <%s>, mid: <%s>, %f, %s, metric: %s: [%f / %f], symbols: ",
							priv->mlfi_id, (mid != NULL) ? mid : "undef",
							tf - ts, selected->name, cur->metric_name,
							cur->score, cur->required_score);
			free (cur->metric_name);
		}
		else {
			if (cfg->extended_spam_headers && !priv->authenticated) {
				hr = snprintf(hdrbuf, sizeof(hdrbuf), "%s: %s [%.2f / %.2f]%c",
						"default",
						cur->score > cur->required_score ? "True" : "False",
						cur->score, cur->required_score,
						TAILQ_FIRST(&cur->symbols) != NULL ? '\n' : ' ');
			}
			r =
					snprintf(rbuf, sizeof(rbuf),
							"spamdscan: scan <%s>, %f, %s, metric: default: [%f / %f], symbols: ",
							priv->mlfi_id, tf - ts, selected->name, cur->score,
							cur->required_score);

		}
		if (cur->action > res_action) {
			res_action = cur->action;
			if (res_action
					== METRIC_ACTION_REWRITE_SUBJECT&& cur->subject != NULL) {
				/* Copy subject as it would be freed further */
				if (*subject != NULL) {
					free (*subject);
				}
				*subject = strdup (cur->subject);
			}
		}
		/* Write symbols */
		cur_symbol = TAILQ_FIRST(&cur->symbols);
		if (cur_symbol == NULL) {
			r += snprintf(rbuf + r, sizeof(rbuf) - r, "no symbols");
		}
		else {
			while (cur_symbol) {
				if (cur_symbol->symbol) {
					if (TAILQ_NEXT(cur_symbol, entry)) {
						r += snprintf(rbuf + r, sizeof(rbuf) - r, "%s, ",
								cur_symbol->symbol);
					}
					else {
						r += snprintf(rbuf + r, sizeof(rbuf) - r, "%s",
								cur_symbol->symbol);
					}
					if (cfg->trace_symbol) {
						c = strchr (cur_symbol->symbol, '(');
						if (c != NULL) {
							*c = '\0';
						}
						if (!strcmp (cfg->trace_symbol, cur_symbol->symbol)) {
							to_trace++;
						}
					}
					if (cfg->extended_spam_headers && !priv->authenticated) {
						if (TAILQ_NEXT(cur_symbol, entry)) {
							hr += snprintf(hdrbuf + hr, sizeof(hdrbuf) - hr,
									" %s\n", cur_symbol->symbol);
						}
						else {
							hr += snprintf(hdrbuf + hr, sizeof(hdrbuf) - hr,
									" %s", cur_symbol->symbol);
						}
					}
					free (cur_symbol->symbol);
				}
				tmp_symbol = cur_symbol;
				cur_symbol = TAILQ_NEXT(cur_symbol, entry);
				free (tmp_symbol);
			}
		}

		msg_info("%s", rbuf);
		if (cur->subject != NULL) {
			free (cur->subject);
		}

		if (cfg->extended_spam_headers && !priv->authenticated) {
			if (extra) {
				smfi_addheader (ctx, "X-Spamd-Extra-Result", hdrbuf);
			}
			else {
				smfi_addheader (ctx, "X-Spamd-Result", hdrbuf);

				j = (int) fabs (cur->score);

				/* Fill spam bar (exim compatible) */
				if (j != 0) {
					char sc = cur->score > 0 ? '+' : '-';

					for (i = 0; i < j; i ++) {
						if (i > 50) {
							break;
						}

						bar_buf[i] = sc;
					}

					bar_buf[i] = '\0';
				}
				else {
					bar_buf[0] = '/';
					bar_buf[1] = '\0';
				}

				smfi_addheader (ctx, "X-Spamd-Bar", bar_buf);

				/*
				 * SA compatible headers:
				 * X-Spam-Level
				 * X-Spam-Status
				 */

				if (cur->score > 0 && cfg->spam_bar_char) {
					for (i = 0; i < (int)cur->score; i ++) {
						if (i > 50) {
							break;
						}

						bar_buf[i] = cfg->spam_bar_char[0];
					}

					bar_buf[i] = '\0';
					smfi_addheader (ctx, "X-Spam-Level", bar_buf);
				}

				snprintf (hdrbuf, sizeof (hdrbuf), "%s, score=%.1f",
						cur->action > METRIC_ACTION_GREYLIST ? "Yes" : "No",
						cur->score);
				smfi_addheader (ctx, "X-Spam-Status", hdrbuf);
			}
		}

		tmp = cur;
		cur = TAILQ_NEXT(cur, entry);
		free (tmp);
	}
	/* All other statistic headers */
	if (cfg->extended_spam_headers && !priv->authenticated) {
		if (extra) {
			smfi_addheader (ctx, "X-Spamd-Extra-Server", selected->name);
			snprintf(hdrbuf, sizeof(hdrbuf), "%.2f", tf - ts);
			smfi_addheader (ctx, "X-Spamd-Extra-Scan-Time", hdrbuf);
		}
		else {
			smfi_addheader (ctx, "X-Spamd-Server", selected->name);
			snprintf(hdrbuf, sizeof(hdrbuf), "%.2f", tf - ts);
			smfi_addheader (ctx, "X-Spamd-Scan-Time", hdrbuf);
			smfi_addheader (ctx, "X-Spamd-Queue-ID", priv->mlfi_id);
		}
	}
	/* Trace spam messages to specific addr */
	if (!extra && to_trace && cfg->trace_addr) {
		smfi_addrcpt (ctx, cfg->trace_addr);
		smfi_setpriv (ctx, priv);
	}

	return (r > 0 ? res_action : r);
}

/*
 * vi:ts=4
 */
