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

#include "radix.h"
#include "cfg_file.h"
#include "rmilter.h"
#include "memcached.h"
#include "upstream.h"
#include "ratelimit.h"

#define EXPIRE_TIME 86400

struct ratelimit_bucket_s {
	double tm;
	double count;
};

enum keytype {
	TO = 0,
	TO_IP,
	TO_IP_FROM,
	BOUNCE_TO,
	BOUNCE_TO_IP
};

/* Convert string to lowercase */
static void
convert_to_lowercase (char *str, unsigned int size)
{
	while (size--) {
		*str = tolower (*str);
		str ++;
	}
}

/* Return lenth of user part */
static size_t
extract_user_part (const char *str)
{
	size_t user_part_len;
	const char *p;

	/* Extract user part from rcpt */
	p = str;
	user_part_len = 0;
	while (*p++) {
		if (*p == '@') {
			break;
		}
		user_part_len ++;
	}

	return user_part_len;
}

static int
is_whitelisted (struct in_addr *addr, const char *rcpt, struct config_file *cfg)
{
	if (is_whitelisted_rcpt (cfg, rcpt, 0) || is_whitelisted_rcpt (cfg, rcpt, 1)) {
		return 1;
	}
	
	if (radix32tree_find (cfg->limit_whitelist_tree, ntohl((uint32_t)addr->s_addr)) != RADIX_NO_VALUE) {
		return 2;
	}

	return 0;
}

static int
is_bounce (char *from, struct config_file *cfg)
{
	size_t user_part_len;
	struct addr_list_entry *cur_addr;

	user_part_len = extract_user_part (from);
	LIST_FOREACH (cur_addr, &cfg->bounce_addrs, next) {
		if (cur_addr->len == user_part_len && strncasecmp (cur_addr->addr, from, user_part_len) == 0) {
			/* Bounce rcpt */
			return 1;
		}
	}

	return 0;
}

static void
make_key (char *buf, size_t buflen, enum keytype type, struct mlfi_priv *priv, const char *rcpt)
{
	int r = 0;
	switch (type) {
		case TO:
			snprintf (buf, buflen, "%s", rcpt);
			break;
		case TO_IP:
			r = snprintf (buf, buflen, "%s:%s", rcpt, priv->priv_ip);
			break;
		case TO_IP_FROM:
			r = snprintf (buf, buflen, "%s:%s:%s", rcpt, priv->priv_ip, priv->priv_from);
			break;
		case BOUNCE_TO:
				snprintf (buf, buflen, "%s:<>", rcpt);
			break;
		case BOUNCE_TO_IP:
			r = snprintf (buf, buflen, "%s:%s:<>",  rcpt, priv->priv_ip);
			break;
	}
	
	convert_to_lowercase (buf, r);
}

static int
check_specific_limit (struct mlfi_priv *priv, struct config_file *cfg,
		enum keytype type, bucket_t *bucket, double tm, const char *rcpt, int is_update)
{
	struct memcached_server *selected;
	struct ratelimit_bucket_s b;
	memcached_ctx_t mctx;
	memcached_param_t cur_param;
	size_t s;
	int r;

	if (bucket->burst == 0 || bucket->rate == 0) {
		return 1;
	}
	
	make_key (cur_param.key, sizeof (cur_param.key), type, priv, rcpt);

	selected = (struct memcached_server *) get_upstream_by_hash ((void *)cfg->memcached_servers_limits,
											cfg->memcached_servers_limits_num, sizeof (struct memcached_server),
											floor(tm), cfg->memcached_error_time, cfg->memcached_dead_time, cfg->memcached_maxerrors,
											cur_param.key, strlen(cur_param.key));
	
	if (selected == NULL) {
		return -1;
	}

	mctx.protocol = cfg->memcached_protocol;
	memcpy(&mctx.addr, &selected->addr[0], sizeof (struct in_addr));
	mctx.port = selected->port[0];
	mctx.timeout = cfg->memcached_connect_timeout;
	mctx.sock = -1;
#ifdef WITH_DEBUG
	mctx.options = MEMC_OPT_DEBUG;
#else
	mctx.options = 0;
#endif
	
	if (memc_init_ctx (&mctx) == -1) {
		upstream_fail (&selected->up, floor (tm));
		return -1;
	}
	
	bzero (&b, sizeof (b));
	cur_param.buf = (void *)&b;
	cur_param.bufsize = sizeof (struct ratelimit_bucket_s);
	s = 1;
	r = memc_get (&mctx, &cur_param, &s);
	if (r != OK && r != NOT_EXISTS) {
		msg_err ("check_specific_limit: got error on 'get' command from memcached server(%s): %s, key: %s", inet_ntoa(selected->addr[0]), memc_strerror (r), cur_param.key);
		memc_close_ctx (&mctx);
		upstream_fail (&selected->up, floor (tm));
		return -1;
	}
	
	msg_debug ("check_specific_limit: got limit for key: '%s', count: %.1f, time: %.1f", cur_param.key, b.count, b.tm);
	/* Leak from bucket at specified rate */
	if (b.count > 0) {
		b.count -= (tm - b.tm) * bucket->rate;
	}
	b.count += is_update;
	b.tm = tm;
	if (b.count < 0) {
		b.count = 0;
	}

	if (is_update && b.count == 0) {
		/* Delete key if bucket is empty */
		msg_debug ("check_specific_limit: delete key '%s' as it is empty", cur_param.key);
		if (mctx.sock != -1) {
			s = 1;
			if (memc_delete (&mctx, &cur_param, &s) != OK) {
				msg_err ("check_specific_limit: got error on 'delete' command from memcached server(%s): %s, key: %s", inet_ntoa(selected->addr[0]), memc_strerror (r), cur_param.key);
				memc_close_ctx (&mctx);
				upstream_fail (&selected->up, floor (tm));
				return -1;
			}
		}
	}
	else {
		/* Update rate limit */
		msg_debug ("check_specific_limit: write limit for key: '%s', count: %.1f, time: %.1f", cur_param.key, b.count, b.tm);
		if (mctx.sock != -1) {
			s = 1;
			if ((r = memc_set (&mctx, &cur_param, &s, EXPIRE_TIME)) != OK) {
				msg_err ("check_specific_limit: got error on 'set' command from memcached server(%s): %s, key: %s", inet_ntoa(selected->addr[0]), memc_strerror (r), cur_param.key);
				memc_close_ctx (&mctx);
				upstream_fail (&selected->up, floor (tm));
				return -1;
			}
		}
	}
	
	memc_close_ctx (&mctx);
	upstream_ok (&selected->up, floor (tm));

	if (b.count > bucket->burst && !is_update) {
		/* Rate limit exceeded */
		msg_err ("rate_check: ratelimit exceeded for key: %s, count: %.2f, burst: %u", cur_param.key, b.count, bucket->burst);
		return 0;
	}
	/* Rate limit not exceeded */
	return 1;
}

int
rate_check (struct mlfi_priv *priv, struct config_file *cfg, const char *rcpt, int is_update)
{
	double t;
	struct timeval tm;
	int r;

	if (priv->priv_addr.family == AF_INET &&
			is_whitelisted (&priv->priv_addr.addr.sa4.sin_addr, rcpt, cfg) != 0) {
		msg_info ("rate_check: address is whitelisted, skipping checks");
		return 1;
	}
	
	tm.tv_sec = priv->conn_tm.tv_sec;
	tm.tv_usec = priv->conn_tm.tv_usec;

	t = tm.tv_sec + tm.tv_usec / 1000000.;

	if (is_bounce (priv->priv_from, cfg) != 0) {
		msg_debug ("rate_check: bounce address detected, doing special checks: %s", priv->priv_from);
		r = check_specific_limit (priv, cfg, BOUNCE_TO, &cfg->limit_bounce_to, t, rcpt, is_update);
		if (r != 1) {
			return r;
		}
		r = check_specific_limit (priv, cfg, BOUNCE_TO_IP, &cfg->limit_bounce_to_ip, t, rcpt, is_update);
		if (r != 1) {
			return r;
		}
	}
	/* Check other limits */
	r = check_specific_limit (priv, cfg, TO_IP_FROM, &cfg->limit_to_ip_from, t, rcpt, is_update);
	if (r != 1) {
		return r;
	}
	r = check_specific_limit (priv, cfg, TO_IP, &cfg->limit_to_ip, t, rcpt, is_update);
	if (r != 1) {
		return r;
	}
	r = check_specific_limit (priv, cfg, TO, &cfg->limit_to, t, rcpt, is_update);
	if (r != 1) {
		return r;
	}
	
	return 1;
}

/* 
 * vi:ts=4 
 */
