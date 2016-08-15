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
#include <math.h>
#include <sys/mman.h>

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
	struct mlfi_priv *priv;
	struct ucl_parser *up;
	ucl_object_t *obj;
	ucl_object_iter_t it = NULL;
	struct rspamd_symbol *sym;
	const ucl_object_t *metric, *elt, *sym_elt;
	const char *act_str;

	priv = res->priv;
	up = ucl_parser_new (0);

	if (!ucl_parser_add_chunk (up, at, length)) {
		msg_err ("<%s>; cannot parse reply from rspamd: %s",
				priv->mlfi_id, ucl_parser_get_error (up));
		ucl_parser_free (up);

		return -1;
	}

	obj = ucl_parser_get_object (up);
	ucl_parser_free (up);
	res->obj = obj;

	if (obj == NULL || ucl_object_type (obj) != UCL_OBJECT) {
		msg_err ("<%s>; cannot parse reply from rspamd: bad top object", priv->mlfi_id);
		ucl_object_unref (obj);

		return -1;
	}

	metric = ucl_object_lookup (obj, "default");

	if (metric == NULL || ucl_object_type (metric) != UCL_OBJECT) {
		msg_err ("<%s>; cannot parse reply from rspamd: no default metric result", priv->mlfi_id);
		ucl_object_unref (obj);

		return -1;
	}

	res->parsed = true;
	elt = ucl_object_lookup (metric, "score");
	res->score = ucl_object_todouble (elt);

	elt = ucl_object_lookup (metric, "required_score");
	res->required_score = ucl_object_todouble (elt);

	elt = ucl_object_lookup (metric, "action");
	act_str = ucl_object_tostring (elt);

	elt = ucl_object_lookup (metric, "subject");
	res->subject = ucl_object_tostring (elt);

	elt = ucl_object_lookup (obj, "message-id");
	res->message_id = ucl_object_tostring (elt);

	elt = ucl_object_lookup (obj, "dkim-signature");
	if (elt) {
		res->dkim_signature = ucl_object_tostring (elt);
	}

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
		else if (strcmp (act_str, "soft reject") == 0) {
			res->action = METRIC_ACTION_SOFT_REJECT;
		}
		else {
			res->action = METRIC_ACTION_NOACTION;
		}
	}
	else {
		msg_warn ("<%s>; invalid reply from rspamd: no action found, assume no action", priv->mlfi_id);
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

static int
rmilter_spamd_symcmp (struct rspamd_symbol *s1, struct rspamd_symbol *s2)
{
	return fabs (s2->score) - fabs (s1->score);
}

/*
 * rspamdscan_socket() - send file to specified host. See spamdscan() for
 * load-balanced wrapper.
 *
 * returns 0 when spam not found, 1 when spam found, -1 on some error during scan (try another server), -2
 * on unexpected error (probably clamd died on our file, fallback to another
 * host not recommended)
 */

static int
rspamdscan_socket(SMFICTX *ctx, struct mlfi_priv *priv,
		const struct spamd_server *srv, struct config_file *cfg,
		struct rspamd_metric_result *res)
{
	sds buf = NULL;
	char *io_buf = NULL;
	struct sockaddr_un server_un;
	struct sockaddr_in server_in;
	int s = -1, fd = -1, ofl, size = 0, ret = -1;
	struct stat sb;
	struct rspamd_metric_result *cur = NULL;
	struct rcpt *rcpt;
	struct rspamd_symbol *cur_symbol;
	struct http_parser parser;
	struct http_parser_settings ps;
	void *map = NULL;
	const size_t iobuf_len = 16384;

	/* somebody doesn't need reply... */
	if (!srv) {
		return -1;
	}

	s = rmilter_connect_addr (srv->name, srv->port, cfg->spamd_connect_timeout, priv);

	if (s == -1) {
		msg_warn("<%s>; rspamd: cannot connect to %s: %s",  priv->mlfi_id,
				srv->name, strerror (errno));
		goto err;
	}

	if (rmilter_poll_fd (s, cfg->spamd_connect_timeout, POLLOUT) < 1) {
		msg_warn("<%s>; rspamd: timeout waiting writing, %s",  priv->mlfi_id, srv->name);
		errno = ETIMEDOUT;
		goto err;
	}

	if (priv->file[0] != '\0') {
		fd = open (priv->file, O_RDONLY);

		if (fd == -1) {
			msg_warn("<%s>; rspamd: open (%s), %s", priv->mlfi_id, srv->name,
					strerror (errno));
			goto err;
		}

		if (fstat (fd, &sb) == -1) {
			msg_warn ("<%s>; rspamd: stat (%s), %s", priv->mlfi_id, srv->name,
					strerror (errno));
			goto err;
		}
	}
	else {
		memset (&sb, 0, sizeof (sb));
	}

	/* Set blocking again */
	ofl = fcntl (s, F_GETFL, 0);
	fcntl (s, F_SETFL, ofl & (~O_NONBLOCK));

	buf = sdsnewlen (NULL, 512);
	sdsclear (buf);
	buf = sdscatfmt (buf,
			"POST /symbols HTTP/1.0\r\nContent-Length: %U\r\n",
			(uint64_t)sb.st_size);

	DL_FOREACH (priv->rcpts, rcpt)
	{
		buf = sdscatfmt (buf, "Rcpt: %s\r\n", rcpt->r_addr);
	}

	if (priv->priv_from[0] != '\0') {
		buf = sdscatfmt (buf, "From: %s\r\n", priv->priv_from);
	}

	if (priv->priv_helo[0] != '\0') {
		buf = sdscatfmt (buf, "Helo: %s\r\n", priv->priv_helo);
	}

	if (priv->priv_hostname[0] != '\0'
			&& memcmp (priv->priv_hostname, "unknown", 8) != 0) {
		buf = sdscatfmt (buf, "Hostname: %s\r\n",
				priv->priv_hostname);
	}

	if (priv->priv_ip[0] != '\0') {
		buf = sdscatfmt (buf, "IP: %s\r\n", priv->priv_ip);
	}

	if (priv->priv_user[0] != '\0') {
		buf = sdscatfmt (buf, "User: %s\r\n", priv->priv_user);
	}

	buf = sdscatfmt (buf, "Queue-ID: %s\r\n", priv->queue_id);

	if (cfg->spamd_settings_id) {
		buf = sdscatfmt (buf, "Settings-ID: %s\r\n", cfg->spamd_settings_id);
	}

	buf = sdscat (buf, "\r\n");

	if (rmilter_atomic_write (s, buf, sdslen (buf)) == -1) {
		msg_warn("<%s>; rspamd: write (%s), %s", priv->mlfi_id, srv->name,
				strerror (errno));
		goto err;
	}

	if (priv->file[0] != '\0') {

		(void)map;
#if defined(FREEBSD) && defined(HAVE_SENDFILE)
		if (sendfile(fd, s, 0, 0, 0, 0, 0) != 0) {
			msg_warn("<%s>; rspamd: sendfile (%s), %s", priv->mlfi_id, srv->name, strerror (errno));
			goto err;
		}
#elif defined(LINUX) && defined(HAVE_SENDFILE)
		off_t off = 0;
		if (sendfile(s, fd, &off, sb.st_size) == -1) {
			msg_warn("<%s>; rspamd: sendfile (%s), %s", priv->mlfi_id, srv->name, strerror (errno));
			goto err;
		}
#else
		map = mmap (NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);

		if (map == MAP_FAILED) {
			map = NULL;
			msg_warn ("<%s>; rspamd: mmap (%s), %s", priv->mlfi_id, srv->name,
					strerror (errno));
			goto err;
		}

		if (rmilter_atomic_write (s, map, sb.st_size) == -1) {
			msg_warn ("<%s>; rspamd: write (%s), %s", priv->mlfi_id, srv->name,
					strerror (errno));
			goto err;
		}

		munmap (map, sb.st_size);
#endif
	}

	fcntl (s, F_SETFL, ofl|O_NONBLOCK);

	/*
	 * read results
	 */
	sdsclear (buf);

	for (;;) {
		ssize_t r;

		if (io_buf == NULL) {
			io_buf = malloc (iobuf_len);
		}

		if (io_buf == NULL) {
			msg_err ("<%s>; rspamd: malloc (%s), %s", priv->mlfi_id, srv->name,
					strerror (errno));
			goto err;
		}

		if (rmilter_poll_fd (s, cfg->spamd_results_timeout, POLLIN) < 1) {
			msg_warn("<%s>; rspamd: timeout waiting results %s", priv->mlfi_id,
					srv->name);
			goto err;
		}

		r = read (s, io_buf, iobuf_len);

		if (r == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				continue;
			}
			else {
				msg_warn("<%s>; rspamd: read, %s, %s", priv->mlfi_id,  srv->name,
						strerror (errno));
				goto err;
			}
		}
		else if (r == 0) {
			break;
		}
		else {
			buf = sdscatlen (buf, io_buf, r);
		}
	}

	size = sdslen (buf);

	if (size == 0) {
		msg_err ("<%s>; rspamd; got empty reply from %s",
				priv->mlfi_id, srv->name);
		goto err;
	}

	/* Now we need to parse HTTP reply */
	memset (&parser, 0, sizeof (parser));
	http_parser_init (&parser, HTTP_RESPONSE);

	memset (&ps, 0, sizeof (ps));
	res->priv = priv;
	ps.on_body = rmilter_spamd_parser_on_body;
	parser.data = res;
	parser.content_length = size;

	if (http_parser_execute (&parser, &ps, buf, size) != (size_t)size) {
		msg_err ("<%s>; rspamd; HTTP parser error: %s when rspamd reply",
				priv->mlfi_id, http_errno_description (parser.http_errno));
		goto err;
	}

	if (!res->parsed) {
		if (parser.status_code != 200) {
			msg_err ("<%s>; rspamd; HTTP error: bad status code: %d",
					priv->mlfi_id, (int)parser.status_code);
		}
		else {
			msg_err ("<%s>; rspamd; HTTP error: cannot parse reply",
					priv->mlfi_id);
		}

		goto err;
	}

	ret = 0;

err:
	if (fd != -1) {
		close (fd);
	}

	if (s != -1) {
		close (s);
	}

	if (buf) {
		sdsfree (buf);
	}

	if (map != NULL) {
		munmap (map, sb.st_size);
	}

	if (io_buf) {
		free (io_buf);
	}

	return ret;
}
#undef TEST_WORD

static void
rmiler_process_rspamd_block (const ucl_object_t *obj, SMFICTX *ctx)
{
	const ucl_object_t *elt, *cur, *cur_elt;
	ucl_object_iter_t it;
	int nhdr;

	if (obj && ucl_object_type (obj) == UCL_OBJECT) {
		elt = ucl_object_lookup (obj, "remove_headers");
		/*
		 * remove_headers:  {"name": 1, ... }
		 * where number is the header's position starting from '1'
		 */
		if (elt && ucl_object_type (elt) == UCL_OBJECT) {
			it = NULL;

			while ((cur = ucl_object_iterate (elt, &it, true)) != NULL) {
				if (ucl_object_type (cur) == UCL_INT) {
					nhdr = ucl_object_toint (cur);

					if (nhdr >= 1) {
						smfi_chgheader (ctx, (char *)ucl_object_key (cur),
								nhdr, NULL);
					}
				}
			}
		}

		elt = ucl_object_lookup (obj, "add_headers");
		/*
		 * add_headers: {"name": "value", ... }
		 * name could have multiple values
		 */
		if (elt && ucl_object_type (elt) == UCL_OBJECT) {
			it = NULL;

			while ((cur = ucl_object_iterate (elt, &it, true)) != NULL) {
				LL_FOREACH (cur, cur_elt) {
					if (ucl_object_type (cur_elt) == UCL_STRING) {
						smfi_addheader (ctx, (char *)ucl_object_key (cur),
								(char *)ucl_object_tostring (cur_elt));
					}
				}
			}
		}
	}
}

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

struct rspamd_metric_result*
spamdscan (void *_ctx, struct mlfi_priv *priv, struct config_file *cfg, int extra)
{
	static const int max_syslog_len = 900;
	int retry, r = -2, to_trace = 0, i, j, ret;
	struct timeval t;
	double ts, tf;
	struct spamd_server *selected = NULL;
	char bar_buf[128], hdrbuf[256];
	char *prefix = "s", *c;
	struct rspamd_metric_result *res;
	struct rspamd_symbol *cur_symbol, *tmp_symbol;
	struct timespec sleep_ts;
	SMFICTX *ctx = _ctx;
	sds optbuf, logbuf, headerbuf;
	const ucl_object_t *obj;
	bool extended_options = true, print_symbols = true;

	gettimeofday (&t, NULL);
	ts = t.tv_sec + t.tv_usec / 1000000.0;
	retry = cfg->spamd_retry_count;
	sleep_ts.tv_sec = cfg->spamd_retry_timeout / 1000;
	sleep_ts.tv_nsec = (cfg->spamd_retry_timeout % 1000) * 1000000ULL;

	res = malloc (sizeof (*res));

	if (res == NULL) {
		msg_err("<%s>; spamdscan: malloc falied, %s", priv->mlfi_id,
				strerror (errno));
		return NULL;
	}

	memset (res, 0, sizeof (*res));

	/* try to scan with available servers */
	while (1) {
		if (extra) {
			selected = (struct spamd_server *) get_random_upstream (
					(void *) cfg->extra_spamd_servers,
					cfg->extra_spamd_servers_num, sizeof(struct spamd_server),
					t.tv_sec, cfg->spamd_error_time, cfg->spamd_dead_time,
					cfg->spamd_maxerrors, priv);
		}
		else {
			selected = (struct spamd_server *) get_random_upstream (
					(void *) cfg->spamd_servers, cfg->spamd_servers_num,
					sizeof(struct spamd_server), t.tv_sec,
					cfg->spamd_error_time, cfg->spamd_dead_time,
					cfg->spamd_maxerrors, priv);
		}
		if (selected == NULL) {
			msg_err("<%s>; spamdscan: upstream get error, %s", priv->mlfi_id,
					priv->file);
			free (res);

			return NULL;
		}

		msg_info ("<%s>; spamdscan: start scanning message on %s", priv->mlfi_id,
				selected->name);

		prefix = "rs";
		r = rspamdscan_socket (ctx, priv, selected, cfg, res);

		msg_info("<%s>; spamdscan: finish scanning message on %s", priv->mlfi_id,
				selected->name);

		if (r == 0 || r == 1) {
			upstream_ok (&selected->up, t.tv_sec);
			break;
		}
		upstream_fail (&selected->up, t.tv_sec);
		if (r == -2) {
			msg_warn("<%s>; %spamdscan: unexpected problem, %s, %s",
					priv->mlfi_id, prefix, selected->name, priv->file);
			break;
		}
		if (--retry < 1) {
			msg_warn("<%s>; %spamdscan: retry limit exceeded, %s, %s",
					priv->mlfi_id, prefix, selected->name, priv->file);
			break;
		}

		msg_warn("<%s>; %spamdscan: failed to scan, retry, %s, %s",
				priv->mlfi_id, prefix, selected->name, priv->file);
		nanosleep (&sleep_ts, NULL);
	}

	if (r < 0) {
		free (res);
		return NULL;
	}

	/*
	 * print scanning time, server and result
	 */
	gettimeofday (&t, NULL);
	tf = t.tv_sec + t.tv_usec / 1000000.0;

	logbuf = sdsnewlen (NULL, 1024);
	headerbuf = sdsnewlen (NULL, 512);

	if (res->symbols) {
		/* Sort symbols by scores from high to low */
		DL_SORT (res->symbols, rmilter_spamd_symcmp);
	}

	if (res->message_id) {
		rmilter_strlcpy (priv->message_id, res->message_id,
				sizeof (priv->message_id));
	}

log_retry:
	sdsclear (logbuf);
	sdsclear (headerbuf);

	/* Parse res tailq */
	if (cfg->extended_spam_headers && !priv->authenticated) {
		headerbuf = sdscatprintf (headerbuf, "%s: %s [%.2f / %.2f]%c",
				"default", res->score > res->required_score ? "True" : "False",
				res->score, res->required_score,
				res->symbols != NULL ? '\n' : ' ');
	}

	logbuf = sdscatprintf (logbuf,
					"<%s>; spamdscan: scan, time: %.3f, server: %s, metric: "
					"default: [%.3f / %.3f], symbols: ",
					priv->mlfi_id, tf - ts, selected->name, res->score,
					res->required_score);

	/* Write symbols */
	if (res->symbols == NULL) {
		logbuf = sdscatprintf (logbuf, "no symbols");
	}
	else {
		optbuf = sdsempty ();

		DL_FOREACH_SAFE (res->symbols, cur_symbol, tmp_symbol) {
			sdsclear (optbuf);

			if (cur_symbol->symbol) {

				if (cur_symbol->options && extended_options) {
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

				if (print_symbols) {
					if (cur_symbol->next) {
						logbuf = sdscatprintf (logbuf, "%s(%.2f)[%s], ",
								cur_symbol->symbol, cur_symbol->score, optbuf);
					}
					else {
						logbuf = sdscatprintf (logbuf, "%s(%.2f)[%s]",
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
				}

				if (cfg->extended_spam_headers && !priv->authenticated) {
					if (cur_symbol->next) {
						headerbuf = sdscatprintf (headerbuf,
								" %s(%.2f)[%s]\n", cur_symbol->symbol,
								cur_symbol->score, optbuf);
					}
					else {
						headerbuf = sdscatprintf (headerbuf,
								" %s(%.2f)[%s]",
								cur_symbol->symbol,
								cur_symbol->score, optbuf);
					}
				}
			}
		}

		sdsfree (optbuf);
	}

	if (sdslen (logbuf) > max_syslog_len) {
		if (extended_options) {
			/* Try to retry without options */
			extended_options = false;
			msg_info ("<%s>; spamdscan: too large reply: %d, skip options",
					priv->mlfi_id, (int)sdslen (logbuf));
			goto log_retry;
		}
		else if (print_symbols) {
			msg_info ("<%s>; spamdscan: too large reply: %d, skip symbols",
					priv->mlfi_id, (int)sdslen (logbuf));
			print_symbols = false;
			goto log_retry;
		}
		else {
			/* Truncate reply */
			msg_err ("<%s>; spamdscan: too large reply: %d, truncate reply",
					priv->mlfi_id, (int)sdslen (logbuf));
			sdsrange (logbuf, 0, max_syslog_len);
		}
	}

	msg_info ("%s", logbuf);
	sdsfree (logbuf);

	if (cfg->extended_spam_headers && !priv->authenticated) {
		if (extra) {
			smfi_addheader (ctx, "X-Spamd-Extra-Result", headerbuf);
		}
		else {
			smfi_addheader (ctx, "X-Spamd-Result", headerbuf);
		}
	}

	sdsfree (headerbuf);

	/* All other statistic headers */
	if (cfg->extended_spam_headers && !priv->authenticated) {
		if (extra) {
			smfi_addheader (ctx, "X-Rspamd-Extra-Server", selected->name);
			snprintf (hdrbuf, sizeof(hdrbuf), "%.2f", tf - ts);
			smfi_addheader (ctx, "X-Rspamd-Extra-Scan-Time", hdrbuf);
		}
		else {
			smfi_addheader (ctx, "X-Rspamd-Server", selected->name);
			snprintf (hdrbuf, sizeof (hdrbuf), "%.2f", tf - ts);
			smfi_addheader (ctx, "X-Rspamd-Scan-Time", hdrbuf);
			smfi_addheader (ctx, "X-Rspamd-Queue-ID", priv->queue_id);
		}
	}

	if (res->dkim_signature) {
		/* Add dkim signature passed from rspamd */
		smfi_addheader (ctx, "DKIM-Signature", (char *)res->dkim_signature);
	}

	obj = ucl_object_lookup (res->obj, "rmilter");
	if (obj) {
		rmiler_process_rspamd_block (obj, ctx);
	}

	/* Trace spam messages to specific addr */
	if (!extra && to_trace && cfg->trace_addr) {
		smfi_addrcpt (ctx, cfg->trace_addr);
		smfi_setpriv (ctx, priv);
	}

	return res;
}

void
spamd_free_result (struct rspamd_metric_result *mres)
{
	struct rspamd_symbol *cur_symbol, *tmp_symbol;

	if (mres) {
		DL_FOREACH_SAFE (mres->symbols, cur_symbol, tmp_symbol) {
			free (cur_symbol);
		}

		ucl_object_unref (mres->obj);
		free (mres);
	}
}
