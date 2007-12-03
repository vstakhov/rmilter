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

#include "cfg_file.h"
#include "rmilter.h"
#include "ratelimit.h"

struct memcached_bucket_s {
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
is_bounce (char *rcpt, struct config_file *cfg)
{
	size_t user_part_len;
	struct addr_list_entry *cur_addr;

	user_part_len = extract_user_part (rcpt);
	LIST_FOREACH (cur_addr, &cfg->bounce_addrs, next) {
		if (cur_addr->len == user_part_len && strncasecmp (cur_addr->addr, rcpt, user_part_len) == 0) {
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
			snprintf (buf, buflen, "%s", priv->priv_cur_rcpt);
			break;
		case TO_IP:
			snprintf (buf, buflen, "%s:%s", priv->priv_cur_rcpt, priv->priv_ip);
			break;
		case TO_IP_FROM:
			snprintf (buf, buflen, "%s:%s:%s", priv->priv_cur_rcpt, priv->priv_ip, priv->priv_from);
			break;
		case BOUNCE_TO:
			snprintf (buf, buflen, "%s:<>", priv->priv_cur_rcpt);
			break;
		case BOUNCE_TO_IP:
			snprintf (buf, buflen, "%s:%s:<>",  priv->priv_cur_rcpt, priv->priv_ip);
			break;
	}
}

int
rate_check (struct mlfi_priv *priv, struct config_file *cfg)
{
	/* XXX: Write this part after writing memcached library */
	return 0;
}

/* 
 * vi:ts=4 
 */
