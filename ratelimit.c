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
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>

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

/* Return lenth of user part */
static size_t
extract_user_part (char *str)
{
	size_t user_part_len;
	char *p;

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
is_whitelisted (struct in_addr *addr, char *rcpt, struct config_file *cfg)
{
	size_t user_part_len;
	struct addr_list_entry *cur_addr;
	struct ip_list_entry *cur_ip;

	user_part_len = extract_user_part (rcpt);
	LIST_FOREACH (cur_addr, &cfg->whitelist_rcpt, next) {
		if (cur_addr->len == user_part_len && strncasecmp (cur_addr->addr, rcpt, user_part_len) == 0) {
			/* Whitelist rcpt */
			return 1;
		}
	}

	LIST_FOREACH (cur_ip, &cfg->whitelist_ip, next) {
		if (memcmp (&cur_ip->addr, addr, sizeof (struct in_addr)) == 0) {
			/* Whitelist ip */
			return 2;
		}
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
make_key (char *buf, size_t buflen, enum keytype type, struct mlfi_priv *priv)
{
	switch (type) {
		case TO:
			snprintf (buf, buflen, "%s", priv->priv_rcpt);
			break;
		case TO_IP:
			snprintf (buf, buflen, "%s:%s", priv->priv_rcpt, priv->priv_ip);
			break;
		case TO_IP_FROM:
			snprintf (buf, buflen, "%s:%s:%s", priv->priv_rcpt, priv->priv_ip, priv->priv_from);
			break;
		case BOUNCE_TO:
			snprintf (buf, buflen, "%s:<>", priv->priv_rcpt);
			break;
		case BOUNCE_TO_IP:
			snprintf (buf, buflen, "%s:%s:<>",  priv->priv_rcpt, priv->priv_ip);
			break;
	}
}

static int
check_specific_limit (struct mlfi_priv *priv, struct config_file *cfg, enum keytype type, bucket_t *bucket, double tm, int is_update)
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
	
	make_key (cur_param.key, sizeof (cur_param.key), type, priv);

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
			if (memc_set (&mctx, &cur_param, &s, EXPIRE_TIME) != OK) {
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
		msg_info ("rate_check: ratelimit exceeded for key: %s, count: %.2f, burst: %u", cur_param.key, b.count, bucket->burst);
		return 0;
	}
	/* Rate limit not exceeded */
	return 1;
}

int
rate_check (struct mlfi_priv *priv, struct config_file *cfg, int is_update)
{
	double t;
	struct timeval tm;
	int r;

	if (is_whitelisted (&priv->priv_addr.sin_addr, priv->priv_rcpt, cfg) != 0) {
		msg_info ("rate_check: address is whitelisted, skipping checks");
		return 1;
	}
	
	tm.tv_sec = priv->conn_tm.tv_sec;
	tm.tv_usec = priv->conn_tm.tv_usec;

	t = tm.tv_sec + tm.tv_usec / 1000000.;

	if (is_bounce (priv->priv_from, cfg) != 0) {
		msg_debug ("rate_check: bounce address detected, doing special checks: %s", priv->priv_from);
		r = check_specific_limit (priv, cfg, BOUNCE_TO, &cfg->limit_bounce_to, t, is_update);
		if (r != 1) {
			return r;
		}
		r = check_specific_limit (priv, cfg, BOUNCE_TO_IP, &cfg->limit_bounce_to_ip, t, is_update);
		if (r != 1) {
			return r;
		}
	}
	/* Check other limits */
	r = check_specific_limit (priv, cfg, TO_IP_FROM, &cfg->limit_to_ip_from, t, is_update);
	if (r != 1) {
		return r;
	}
	r = check_specific_limit (priv, cfg, TO_IP, &cfg->limit_to_ip, t, is_update);
	if (r != 1) {
		return r;
	}
	r = check_specific_limit (priv, cfg, TO, &cfg->limit_to, t, is_update);
	if (r != 1) {
		return r;
	}
	
	return 1;
}

/* 
 * vi:ts=4 
 */
