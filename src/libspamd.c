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
#include "ucl.h"
#include "http_parser.h"
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

static int
rmilter_spamd_parser_on_body (http_parser * parser, const char *at, size_t length)
{
	struct rspamd_metric_result *res = parser->data;
	struct ucl_parser *up;
	ucl_object_t *obj;
	ucl_object_iter_t it = NULL;
	struct rspamd_symbol *sym;
	const ucl_object_t *metric, *elt, *sym_elt;
	const char *act_str;

	up = ucl_parser_new (0);

	if (!ucl_parser_add_chunk (up, at, length)) {
		msg_err ("cannot parse reply from rspamd: %s",
				ucl_parser_get_error (up));
		ucl_parser_free (up);

		return -1;
	}

	obj = ucl_parser_get_object (up);
	ucl_parser_free (up);
	res->obj = obj;

	if (obj == NULL || ucl_object_type (obj) != UCL_OBJECT) {
		msg_err ("cannot parse reply from rspamd: bad top object");
		ucl_object_unref (obj);

		return -1;
	}

	metric = ucl_object_lookup (obj, "default");

	if (metric == NULL || ucl_object_type (metric) != UCL_OBJECT) {
		msg_err ("cannot parse reply from rspamd: no default metric result");
		ucl_object_unref (obj);

		return -1;
	}

	elt = ucl_object_lookup (metric, "score");
	res->score = ucl_object_todouble (elt);

	elt = ucl_object_lookup (metric, "required_score");
	res->required_score = ucl_object_todouble (elt);

	elt = ucl_object_lookup (metric, "action");
	act_str = ucl_object_tostring (elt);

	elt = ucl_object_lookup (metric, "subject");
	res->subject = ucl_object_tostring (elt);

	if (act_str) {
		if (strcmp (act_str, "reject") == 0) {
			res->action = METRIC_ACTION_REJECT;
		}
		else if (strcmp (act_str, "greylist") == 0) {
			res->action = METRIC_ACTION_GREYLIST;
		}
		else if (strcmp (act_str, "add header") == 0) {
			res->action = METRIC_ACTION_ADD_HEADER;
		}
		else if (strcmp (act_str, "rewrite subject") == 0) {
			res->action = METRIC_ACTION_REWRITE_SUBJECT;
		}
		else {
			msg_warn ("invalid reply from rspamd: bad action %s", act_str);
			res->action = METRIC_ACTION_NOACTION;
		}
	}
	else {
		msg_warn ("invalid reply from rspamd: no action found, assume no action");
		res->action = METRIC_ACTION_NOACTION;
	}

	while ((sym_elt = ucl_object_iterate (metric, &it, true)) != NULL) {
		/* Here we assume that all objects found here are symbols */
		if (ucl_object_type (sym_elt) == UCL_OBJECT) {
			sym = malloc (sizeof (*sym));

			if (sym != NULL) {
				sym->symbol = ucl_object_key (sym_elt);
				elt = ucl_object_lookup (sym_elt, "score");
				sym->score = ucl_object_todouble (elt);
				sym->options = ucl_object_lookup (sym_elt, "options");

				DL_APPEND (res->symbols, sym);
			}
		}
	}

	return 0;
}

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
		struct rspamd_metric_result *res, char **mid)
{
	char buf[8192];
	sds readbuf;
	struct sockaddr_un server_un;
	struct sockaddr_in server_in;
	int s, r, fd, ofl, size = 0, to_write, written;
	struct stat sb;
	struct rspamd_metric_result *cur = NULL;
	struct rcpt *rcpt;
	struct rspamd_symbol *cur_symbol;
	struct http_parser parser;
	struct http_parser_settings ps;
	struct iovec iov[2];

	/* somebody doesn't need reply... */
	if (!srv) {
		return 0;
	}

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
	to_write = sizeof (buf) - r;
	written = snprintf (buf + r, to_write,
			"GET /symbols HTTP/1.0\r\nContent-Length: %ld\r\n",
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
	written = snprintf(buf + r, to_write, "Queue-ID: %s\r\n",
			priv->mlfi_id);
	if (written > to_write) {
		msg_warn("<%s> rspamd: buffer overflow while filling buffer (%s)",
				 priv->mlfi_id, srv->name);
		close (fd);
		close (s);
		return -1;
	}
	r += written;

	if (cfg->spamd_settings_id) {
		to_write = sizeof(buf) - r;
		written = snprintf(buf + r, to_write, "Settings-ID: %s\r\n",
				cfg->spamd_settings_id);
		if (written > to_write) {
			msg_warn("<%s> rspamd: buffer overflow while filling buffer (%s)",
					priv->mlfi_id, srv->name);
			close (fd);
			close (s);
			return -1;
		}
		r += written;
	}

	iov[0].iov_base = buf;
	iov[0].iov_len = r;
	iov[1].iov_base = "\r\n";
	iov[1].iov_len = 2;

	if (writev (s, iov, sizeof (iov) / sizeof (iov[0])) == -1) {
		msg_warn("<%s> rspamd: writev (%s), %s", priv->mlfi_id, srv->name,
				strerror (errno));
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

	/* Now we need to parse HTTP reply */
	memset (&parser, 0, sizeof (parser));
	http_parser_init (&parser, HTTP_RESPONSE);

	memset (&ps, 0, sizeof (ps));
	ps.on_body = rmilter_spamd_parser_on_body;
	parser.data = res;
	parser.content_length = size;

	if (http_parser_execute (&parser, &ps, readbuf, size) != (size_t)size) {
		msg_err ("HTTP parser error: %s when rspamd reply",
				http_errno_description (parser.http_errno));
		return -1;
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

int
spamdscan (void *_ctx, struct mlfi_priv *priv, struct config_file *cfg,
		char **subject, int extra)
{
	int retry, r = -2, hr = 0, to_trace = 0, i, j, ret;
	struct timeval t;
	double ts, tf;
	struct spamd_server *selected = NULL;
	char rbuf[1024], hdrbuf[1024], bar_buf[128];
	char *prefix = "s", *mid = NULL, *c;
	struct rspamd_metric_result res;
	struct rspamd_symbol *cur_symbol, *tmp_symbol;
	struct timespec sleep_ts;
	SMFICTX *ctx = _ctx;
	sds optbuf;

	gettimeofday (&t, NULL);
	ts = t.tv_sec + t.tv_usec / 1000000.0;
	retry = cfg->spamd_retry_count;
	sleep_ts.tv_sec = cfg->spamd_retry_timeout / 1000;
	sleep_ts.tv_nsec = (cfg->spamd_retry_timeout % 1000) * 1000000ULL;
	memset (&res, 0, sizeof (res));

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

		msg_info("<%s> spamdscan: finish scanning message on %s", priv->mlfi_id,
				selected->name);

		if (r == 0 || r == 1) {
			upstream_ok (&selected->up, t.tv_sec);
			break;
		}
		upstream_fail (&selected->up, t.tv_sec);
		if (r == -2) {
			msg_warn("<%s> %spamdscan: unexpected problem, %s, %s",
					priv->mlfi_id, prefix, selected->name, priv->file);
			break;
		}
		if (--retry < 1) {
			msg_warn("<%s> %spamdscan: retry limit exceeded, %s, %s",
					priv->mlfi_id, prefix, selected->name, priv->file);
			break;
		}

		msg_warn("<%s> %spamdscan: failed to scan, retry, %s, %s",
				priv->mlfi_id, prefix, selected->name, priv->file);
		nanosleep (&sleep_ts, NULL);
	}

	/*
	 * print scanning time, server and result
	 */
	gettimeofday (&t, NULL);
	tf = t.tv_sec + t.tv_usec / 1000000.0;

	/* Parse res tailq */
	if (cfg->extended_spam_headers && !priv->authenticated) {
		hr = snprintf(hdrbuf, sizeof(hdrbuf), "%s: %s [%.2f / %.2f]%c",
				"default", res.score > res.required_score ? "True" : "False",
				res.score, res.required_score,
				res.symbols != NULL ? '\n' : ' ');
	}
	r =
			snprintf(rbuf, sizeof(rbuf),
					"spamdscan: scan <%s>, %f, %s, metric: default: [%f / %f], symbols: ",
					priv->mlfi_id, tf - ts, selected->name, res.score,
					res.required_score);

	if (res.action == METRIC_ACTION_REWRITE_SUBJECT && res.subject != NULL) {
		*subject = strdup (res.subject);
	}

	/* Write symbols */
	if (res.symbols == NULL) {
		r += snprintf (rbuf + r, sizeof(rbuf) - r, "no symbols");
	}
	else {
		optbuf = sdsempty ();

		DL_FOREACH_SAFE (res.symbols, cur_symbol, tmp_symbol) {
			sdsclear (optbuf);

			if (cur_symbol->symbol) {

				if (cur_symbol->options) {
					ucl_object_iter_t it = NULL;
					const ucl_object_t *elt;
					bool first = true;

					while ((elt = ucl_object_iterate (cur_symbol->options,
							&it, true)) != NULL) {
						if (ucl_object_type (elt) == UCL_STRING) {
							if (first) {
								optbuf = sdscat (optbuf,
										ucl_object_tostring (elt));
								first = false;
							}
							else {
								optbuf = sdscat (optbuf, ", ");
								optbuf = sdscat (optbuf,
										ucl_object_tostring (elt));
							}
						}
					}
				}

				if (cur_symbol->next) {
					r += snprintf(rbuf + r, sizeof(rbuf) - r, "%s(%.2f)[%s], ",
							cur_symbol->symbol, cur_symbol->score, optbuf);
				}
				else {
					r += snprintf(rbuf + r, sizeof(rbuf) - r, "%s(%.2f)[%s]",
							cur_symbol->symbol, cur_symbol->score, optbuf);
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
					if (cur_symbol->next) {
						hr += snprintf(hdrbuf + hr, sizeof(hdrbuf) - hr,
								" %s(%.2f)[%s]\n", cur_symbol->symbol,
								cur_symbol->score, optbuf);
					}
					else {
						hr += snprintf(hdrbuf + hr, sizeof(hdrbuf) - hr, " "
								"%s(%.2f)[%s]",
								cur_symbol->symbol,
								cur_symbol->score, optbuf);
					}
				}
			}

			free (cur_symbol);
		}

		sdsfree (optbuf);
	}

	msg_info("%s", rbuf);

	if (cfg->extended_spam_headers && !priv->authenticated) {
		if (extra) {
			smfi_addheader (ctx, "X-Spamd-Extra-Result", hdrbuf);
		}
		else {
			smfi_addheader (ctx, "X-Spamd-Result", hdrbuf);

			j = (int) fabs (res.score);

			/* Fill spam bar (exim compatible) */
			if (j != 0) {
				char sc = res.score > 0 ? '+' : '-';

				for (i = 0; i < j; i++) {
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

			if (res.score > 0 && cfg->spam_bar_char) {
				for (i = 0; i < (int) res.score; i++) {
					if (i > 50) {
						break;
					}

					bar_buf[i] = cfg->spam_bar_char[0];
				}

				bar_buf[i] = '\0';
				smfi_addheader (ctx, "X-Spam-Level", bar_buf);
			}

			snprintf(hdrbuf, sizeof(hdrbuf), "%s, score=%.1f",
					res.action > METRIC_ACTION_GREYLIST ? "Yes" : "No",
					res.score);
			smfi_addheader (ctx, "X-Spam-Status", hdrbuf);
		}
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

	ret =  (r > 0 ? res.action : r);

	ucl_object_unref (res.obj);

	return ret;
}

/*
 * vi:ts=4
 */
