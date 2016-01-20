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
#include "cache.h"
#include "upstream.h"
#include "ratelimit.h"

#define EXPIRE_TIME 86400

struct ratelimit_bucket_s
{
	double tm;
	double count;
};

enum keytype
{
	TO = 0, TO_IP, TO_IP_FROM, BOUNCE_TO, BOUNCE_TO_IP
};

/* Convert string to lowercase */
static void convert_to_lowercase(char *str, unsigned int size)
{
	while (size--) {
		*str = tolower (*str);
		str++;
	}
}

/* Return lenth of user part */
static size_t extract_user_part(const char *str)
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
		user_part_len++;
	}

	return user_part_len;
}

static int
is_whitelisted (struct rmilter_inet_address *addr, const char *rcpt,
		struct config_file *cfg)
{
	if (is_whitelisted_rcpt (cfg, rcpt, 0)
			|| is_whitelisted_rcpt (cfg, rcpt, 1)) {
		return 1;
	}

	if (radix_find_rmilter_addr (cfg->limit_whitelist_tree, addr)
			!= RADIX_NO_VALUE) {
		return 2;
	}

	return 0;
}

static int is_bounce(char *from, struct config_file *cfg)
{
	size_t user_part_len;
	struct addr_list_entry *cur_addr;

	user_part_len = extract_user_part (from);
	LIST_FOREACH (cur_addr, &cfg->bounce_addrs, next)
	{
		if (cur_addr->len == user_part_len
				&& strncasecmp (cur_addr->addr, from, user_part_len) == 0) {
			/* Bounce rcpt */
			return 1;
		}
	}

	return 0;
}

static int make_key(char *buf, size_t buflen, enum keytype type,
		struct mlfi_priv *priv, const char *rcpt)
{
	int r = 0;
	switch (type) {
	case TO:
		r = snprintf(buf, buflen, "%s", rcpt);
		break;
	case TO_IP:
		r = snprintf(buf, buflen, "%s:%s", rcpt, priv->priv_ip);
		break;
	case TO_IP_FROM:
		r = snprintf(buf, buflen, "%s:%s:%s", rcpt, priv->priv_ip,
				priv->priv_from);
		break;
	case BOUNCE_TO:
		r = snprintf(buf, buflen, "%s:<>", rcpt);
		break;
	case BOUNCE_TO_IP:
		r = snprintf(buf, buflen, "%s:%s:<>", rcpt, priv->priv_ip);
		break;
	}

	if (r >= buflen) {
		return 0;
	}

	convert_to_lowercase (buf, r);

	return r;
}

static int check_specific_limit(struct mlfi_priv *priv, struct config_file *cfg,
		enum keytype type, bucket_t *bucket, double tm, const char *rcpt,
		int is_update)
{
	struct memcached_server *selected;
	struct ratelimit_bucket_s *b;
	char key[MAXKEYLEN];
	size_t klen, dlen;

	if (bucket->burst == 0 || bucket->rate == 0) {
		return 1;
	}

	klen = make_key (key, sizeof(key), type, priv, rcpt);

	if (klen == 0) {
		msg_err("check_specific_limit: got error bad too long key");
		return -1;
	}

	dlen = sizeof (*b);

	if (!rmilter_query_cache (cfg, RMILTER_QUERY_RATELIMIT, key, klen,
			(unsigned char **) &b, &dlen)) {
		b = calloc (1, sizeof (*b));
		dlen = sizeof (*b);

		if (b == NULL) {
			msg_err("check_specific_limit: calloc failed: %s", strerror (errno));
			return -1;
		}
	}

	msg_debug("check_specific_limit: got limit for key: '%s', "
			"count: %.1f, time: %.1f", key, b->count, b->tm);
	/* Leak from bucket at specified rate */
	if (b->count > 0) {
		b->count -= (tm - b->tm) * bucket->rate;
	}

	b->count += is_update;
	b->tm = tm;
	if (b->count < 0) {
		b->count = 0;
	}

	if (is_update && b->count == 0) {
		/* Delete key if bucket is empty */
		rmilter_delete_cache (cfg, RMILTER_QUERY_RATELIMIT, key, klen);
	}
	else {
		/* Update rate limit */
		rmilter_set_cache (cfg, RMILTER_QUERY_RATELIMIT, key, klen,
				(unsigned char *) b, dlen, EXPIRE_TIME);
	}

	if (b->count > bucket->burst && !is_update) {
		/* Rate limit exceeded */
		msg_info(
				"rate_check: ratelimit exceeded for key: %s, count: %.2f, burst: %u",
				key, b->count, bucket->burst);
		free (b);

		return 0;
	}

	free (b);
	/* Rate limit not exceeded */
	return 1;
}

int rate_check(struct mlfi_priv *priv, struct config_file *cfg,
		const char *rcpt, int is_update)
{
	double t;
	struct timeval tm;
	int r;

	if (priv->priv_addr.family == AF_INET
			&& is_whitelisted (&priv->priv_addr, rcpt, cfg)
					!= 0) {
		msg_info("rate_check: address is whitelisted, skipping checks");
		return 1;
	}

	tm.tv_sec = priv->conn_tm.tv_sec;
	tm.tv_usec = priv->conn_tm.tv_usec;

	t = tm.tv_sec + tm.tv_usec / 1000000.;

	if (is_bounce (priv->priv_from, cfg) != 0) {
		msg_debug(
				"rate_check: bounce address detected, doing special checks: %s",
				priv->priv_from);
		r = check_specific_limit (priv, cfg, BOUNCE_TO, &cfg->limit_bounce_to,
				t, rcpt, is_update);
		if (r != 1) {
			return r;
		}
		r = check_specific_limit (priv, cfg, BOUNCE_TO_IP,
				&cfg->limit_bounce_to_ip, t, rcpt, is_update);
		if (r != 1) {
			return r;
		}
	}
	/* Check other limits */
	r = check_specific_limit (priv, cfg, TO_IP_FROM, &cfg->limit_to_ip_from, t,
			rcpt, is_update);
	if (r != 1) {
		return r;
	}
	r = check_specific_limit (priv, cfg, TO_IP, &cfg->limit_to_ip, t, rcpt,
			is_update);
	if (r != 1) {
		return r;
	}
	r = check_specific_limit (priv, cfg, TO, &cfg->limit_to, t, rcpt,
			is_update);
	if (r != 1) {
		return r;
	}

	return 1;
}

/* 
 * vi:ts=4 
 */
