/******************************************************************************

	Rambler Milter

	$Id$

******************************************************************************/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sysexits.h>
#include <unistd.h>
#include <syslog.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include "md5.h"

/* XXX hack to work on FreeBSD < 7 */
#include <libmilter/mfapi.h>
#include "spf2/spf.h"

#include "libclamc.h"
#include "libspamd.h"
#include "cfg_file.h"
#include "spf.h"
#include "rmilter.h"
#include "regexp.h"
#ifdef HAVE_DCC
#include "dccif.h"
#endif
#include "ratelimit.h"

#ifndef true
typedef int bool;
#define false	0
#define true	1
#endif				/* ! true */

#define MD5_SIZE 16

#define GREY_GREYLISTED 1
#define GREY_WHITELISTED 2
#define GREY_ERROR -1

static sfsistat mlfi_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat mlfi_helo(SMFICTX *, char *);
static sfsistat mlfi_envfrom(SMFICTX *, char **);
static sfsistat mlfi_envrcpt(SMFICTX *, char **);
static sfsistat mlfi_data(SMFICTX *);
static sfsistat mlfi_header(SMFICTX * , char *, char *);
static sfsistat mlfi_eoh(SMFICTX *);
static sfsistat mlfi_body(SMFICTX *, u_char *, size_t);
static sfsistat mlfi_eom(SMFICTX *);
static sfsistat mlfi_close(SMFICTX *);
static sfsistat mlfi_abort(SMFICTX *);
static sfsistat mlfi_cleanup(SMFICTX *, bool);
static int check_clamscan(const char *, char *, size_t);
#ifdef HAVE_DCC
static int check_dcc(const struct mlfi_priv *);
#endif

struct smfiDesc smfilter =
{
    	"rmilter",		/* filter name */
    	SMFI_VERSION,	/* version code -- do not change */
    	SMFIF_ADDHDRS,	/* flags */
    	mlfi_connect,	/* connection info filter */
    	mlfi_helo,		/* SMTP HELO command filter */
    	mlfi_envfrom,	/* envelope sender filter */
    	mlfi_envrcpt,	/* envelope recipient filter */
    	mlfi_header,	/* header filter */
    	mlfi_eoh,		/* end of header */
    	mlfi_body,		/* body block filter */
    	mlfi_eom,		/* end of message */
    	mlfi_abort,		/* message aborted */
    	mlfi_close,		/* connection cleanup */
#if (SMFI_PROT_VERSION > 4)
		NULL,			/* unknown situation */
		mlfi_data,		/* SMTP DATA callback */
		NULL			/* Negotiation callback */
#endif
};

extern struct config_file *cfg;

/* Milter mutexes */
pthread_mutex_t mkstemp_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t regexp_mtx = PTHREAD_MUTEX_INITIALIZER;

static sfsistat
set_reply (SMFICTX *ctx, const struct action *act)
{
	int result = SMFIS_CONTINUE;

	switch (act->type) {
		case ACTION_ACCEPT:
			result = SMFIS_ACCEPT;
			break;
		case ACTION_REJECT:
			result = SMFIS_REJECT;
			break;
		case ACTION_TEMPFAIL:
			result = SMFIS_TEMPFAIL;
			break;
		case ACTION_QUARANTINE:
			result = SMFIS_DISCARD;
			break;
		case ACTION_DISCARD:
			result = SMFIS_DISCARD;
			break;
	}
	if (act->type == ACTION_REJECT &&
	    smfi_setreply(ctx, RCODE_REJECT, XCODE_REJECT,
		(char *)act->message) != MI_SUCCESS) {
		msg_err("smfi_setreply");
	}
	if (act->type == ACTION_TEMPFAIL &&
		smfi_setreply(ctx, RCODE_TEMPFAIL, XCODE_TEMPFAIL,
		(char *)act->message) != MI_SUCCESS) {
		msg_err("smfi_setreply");
	}

	return result;
}

static inline int
is_whitelisted_rcpt (const char *str)
{
	return (strncasecmp (str, "postmaster@", sizeof ("postmaster@") - 1) == 0 ||
			strncasecmp (str, "abuse@", sizeof ("abuse@") - 1) == 0);
}

static inline void
copy_alive (struct memcached_server *srv, const memcached_ctx_t mctx[2]) 
{
	srv->alive[0] = mctx[0].alive;
	srv->alive[1] = mctx[1].alive;
}

static void
check_message_id (struct mlfi_priv *priv, char *header) 
{
	MD5_CTX mdctx;
	u_char final[MD5_SIZE], param = '0';
	char md5_out[MD5_SIZE * 2 + 1], *c;
	struct memcached_server *selected;
	memcached_ctx_t mctx;
	memcached_param_t cur_param;
	int r;
	size_t s = 1;
	
	if (cfg->memcached_servers_id_num == 0) {
		return;
	}

	bzero (&cur_param, sizeof (cur_param));

	cur_param.buf = &param;
	cur_param.bufsize = sizeof (param);

	MD5Init(&mdctx);
	/* Check reply message id in memcached */
	/* Make hash from message id */
	MD5Update(&mdctx, (const u_char *)header, strlen(header));
	MD5Final(final, &mdctx);

	/* Format md5 output */
	s = sizeof (md5_out);
	for (r = 0; r < MD5_SIZE; r ++){
		s -= snprintf (md5_out + r * 2, s, "%02x", final[r]);
	}

	c = cur_param.key;
	s = sizeof (cur_param.key);
	if (cfg->id_prefix) {
		s = strlcpy (c, cfg->id_prefix, s);
		c += s;
	}
	if (sizeof (cur_param.key) - s > sizeof (md5_out)) {
 		memcpy (c, md5_out, sizeof (md5_out));
 	}
 	else {
 		msg_warn ("check_id: id_prefix(%s) too long for memcached key, error in configure", cfg->id_prefix);
 	}

	selected = (struct memcached_server *) get_upstream_by_hash ((void *)cfg->memcached_servers_id,
										cfg->memcached_servers_id_num, sizeof (struct memcached_server),
										(time_t)priv->conn_tm.tv_sec, cfg->memcached_error_time, 
										cfg->memcached_dead_time, cfg->memcached_maxerrors,
										(char *)cur_param.key, strlen (cur_param.key));
	if (selected == NULL) {
		msg_err ("mlfi_data: cannot get memcached upstream for storing message id");
		return;
	}

	mctx.protocol = cfg->memcached_protocol;
	memcpy(&mctx.addr, &selected->addr[0], sizeof (struct in_addr));
	mctx.port = selected->port[0];
	mctx.timeout = cfg->memcached_connect_timeout;
	mctx.alive = selected->alive[0];
#ifdef WITH_DEBUG
	mctx.options = MEMC_OPT_DEBUG;
#else
	mctx.options = 0;
#endif
	
	r = memc_init_ctx(&mctx);
	if (r == -1) {
		msg_warn ("mlfi_data: cannot connect to memcached upstream: %s", inet_ntoa (selected->addr[0]));
		upstream_fail (&selected->up, priv->conn_tm.tv_sec);
		return;
	}
	r = OK;

	r = memc_get (&mctx, &cur_param, &s);
	if (r == OK) {
		/* Turn off strict checks if message id is found */
		memc_close_ctx (&mctx);
		upstream_ok (&selected->up, priv->conn_tm.tv_sec);
		priv->strict = 0;
		strlcpy (priv->reply_id, header, sizeof (priv->reply_id));
		return;
	}
	else if (r != NOT_EXISTS) {
		msg_info ("mlfi_data: cannot read data from memcached: %s", memc_strerror (r));
		upstream_fail (&selected->up, priv->conn_tm.tv_sec);
		memc_close_ctx (&mctx);
		return;
	}
	memc_close_ctx (&mctx);

}

static int
check_greylisting (struct mlfi_priv *priv) 
{
	MD5_CTX mdctx;
	u_char final[MD5_SIZE];
	char md5_out[MD5_SIZE * 2 + 1], *c;
	struct memcached_server *selected;
	memcached_ctx_t mctx[2], mctx_white[2];
	memcached_param_t cur_param;
	struct timeval tm, tm1;
	int r;
	size_t s;

	/* Check whitelist */
	if (radix32tree_find (cfg->grey_whitelist_tree, ntohl((uint32_t)priv->priv_addr.sin_addr.s_addr)) == RADIX_NO_VALUE) {
		if (cfg->awl_enable && awl_check ((uint32_t)priv->priv_addr.sin_addr.s_addr, cfg->awl_hash, priv->conn_tm.tv_sec) == 1) {
			/* Auto whitelisted */
			return GREY_WHITELISTED;
		}

		bzero (&cur_param, sizeof (cur_param));
		MD5Init(&mdctx);
		/* Make hash from components: envfrom, ip address, envrcpt */
		MD5Update(&mdctx, (const u_char *)priv->priv_from, strlen(priv->priv_from));
		MD5Update(&mdctx, (const u_char *)priv->priv_ip, strlen(priv->priv_ip));
		MD5Update(&mdctx, (const u_char *)priv->priv_rcpt, strlen(priv->priv_rcpt));
		MD5Final(final, &mdctx);
		
		tm.tv_sec = priv->conn_tm.tv_sec;
		tm.tv_usec = priv->conn_tm.tv_usec;
		/* Format md5 output */
		s = sizeof (md5_out);
		for (r = 0; r < MD5_SIZE; r ++){
			s -= snprintf (md5_out + r * 2, s, "%02x", final[r]);
		}

		c = cur_param.key;
		s = sizeof (cur_param.key);
		if (cfg->white_prefix) {
			s = strlcpy (c, cfg->white_prefix, s);
			c += s;
		}
		if (sizeof (cur_param.key) - s > sizeof (md5_out)) {
			memcpy (c, md5_out, sizeof (md5_out));
		}
		else {
			msg_warn ("check_greylisting: white_prefix(%s) too long for memcached key, error in configure", cfg->white_prefix);
			memcpy (cur_param.key, md5_out, sizeof (md5_out));
		}

		msg_debug ("check_greylisting: check from: %s@%s to: %s, md5: %s, time: %ld.%ld", priv->priv_from, 
							priv->priv_ip, priv->priv_rcpt, cur_param.key, (long int)tm.tv_sec, (long int)tm.tv_usec);
		s = 1;
		cur_param.buf = (u_char *)&tm1;
		cur_param.bufsize = sizeof (tm1);

		/* Check whitelist memcached */
		selected = (struct memcached_server *) get_upstream_by_hash ((void *)cfg->memcached_servers_white,
										cfg->memcached_servers_white_num, sizeof (struct memcached_server),
										(time_t)tm.tv_sec, cfg->memcached_error_time, cfg->memcached_dead_time, cfg->memcached_maxerrors,
										(char *)final, MD5_SIZE);
		if (selected == NULL) {
			if (cfg->memcached_servers_white_num != 0) {
				msg_err ("check_greylisting: cannot get memcached upstream");
			}
		}
		else {
			mctx_white[0].protocol = cfg->memcached_protocol;
			memcpy(&mctx_white[0].addr, &selected->addr[0], sizeof (struct in_addr));
			mctx_white[0].port = selected->port[0];
			mctx_white[0].timeout = cfg->memcached_connect_timeout;
			mctx_white[0].alive = selected->alive[0];
			if (selected->num == 2) {
				mctx_white[1].protocol = cfg->memcached_protocol;
				memcpy(&mctx_white[1].addr, &selected->addr[1], sizeof (struct in_addr));
				mctx_white[1].port = selected->port[1];
				mctx_white[1].timeout = cfg->memcached_connect_timeout;
				mctx_white[1].alive = selected->alive[0];
			}
			else {
				mctx_white[1].alive = 0;
			}
			/* Reviving upstreams if all are dead */
			if (mctx_white[0].alive == 0 && mctx_white[1].alive == 0) {
				mctx_white[0].alive = 1;
				mctx_white[1].alive = 1;
				copy_alive (selected, mctx_white);
			}
#ifdef WITH_DEBUG
			mctx_white[0].options = MEMC_OPT_DEBUG;
			mctx_white[1].options = MEMC_OPT_DEBUG;
#else
			mctx_white[0].options = 0;
			mctx_white[1].options = 0;
#endif
			
			r = memc_init_ctx_mirror (mctx_white, 2);
			copy_alive (selected, mctx_white);
			if (r == -1) {
				msg_warn ("check_greylisting: cannot connect to memcached upstream: %s", inet_ntoa (selected->addr[0]));
				upstream_fail (&selected->up, tm.tv_sec);
			}
			else {
				r = memc_get_mirror (mctx_white, 2, &cur_param, &s);
				copy_alive (selected, mctx_white);
				if (r == OK) {
					/* Do not check anything if whitelist is found */
					msg_debug ("check_greylisting: hash is in whitelist from: %s@%s to: %s, md5: %s, time: %ld.%ld", priv->priv_from, 
							priv->priv_ip, priv->priv_rcpt, cur_param.key, (long int)tm1.tv_sec, (long int)tm1.tv_usec);
					memc_close_ctx_mirror (mctx_white, 2);
					upstream_ok (&selected->up, tm.tv_sec);
					return GREY_WHITELISTED;
				}
				memc_close_ctx_mirror (mctx_white, 2);
			}
		}
		
		c = cur_param.key;
		s = sizeof (cur_param.key);
		if (cfg->grey_prefix) {
			s = strlcpy (c, cfg->grey_prefix, s);
			c += s;
		}
		if (sizeof (cur_param.key) - s > sizeof (md5_out)) {
			memcpy (c, md5_out, sizeof (md5_out));
		}
		else {
			msg_warn ("check_greylisting: grey_prefix(%s) too long for memcached key, error in configure", cfg->grey_prefix);
			memcpy (cur_param.key, md5_out, sizeof (md5_out));
		}
		/* Try to get record from memcached_grey */
		selected = (struct memcached_server *) get_upstream_by_hash ((void *)cfg->memcached_servers_grey,
										cfg->memcached_servers_grey_num, sizeof (struct memcached_server),
										(time_t)tm.tv_sec, cfg->memcached_error_time, cfg->memcached_dead_time, cfg->memcached_maxerrors,
										(char *)final, MD5_SIZE);
		if (selected == NULL) {
			msg_err ("check_greylisting: cannot get memcached upstream");
			return GREY_ERROR;
		}
		mctx[0].protocol = cfg->memcached_protocol;
		memcpy(&mctx[0].addr, &selected->addr[0], sizeof (struct in_addr));
		mctx[0].port = selected->port[0];
		mctx[0].timeout = cfg->memcached_connect_timeout;
		mctx[0].alive = selected->alive[0];
		if (selected->num == 2) {
			mctx[1].protocol = cfg->memcached_protocol;
			memcpy(&mctx[1].addr, &selected->addr[1], sizeof (struct in_addr));
			mctx[1].port = selected->port[1];
			mctx[1].timeout = cfg->memcached_connect_timeout;
			mctx[1].alive = selected->alive[1];
		}
		else {
			mctx[1].alive = 0;
		}
		/* Reviving upstreams if all are dead */
		if (mctx[0].alive == 0 && mctx[1].alive == 0) {
			mctx[0].alive = 1;
			mctx[1].alive = 1;
			copy_alive (selected, mctx);
		}
#ifdef WITH_DEBUG
		mctx[0].options = MEMC_OPT_DEBUG;
		mctx[1].options = MEMC_OPT_DEBUG;
#else
		mctx[0].options = 0;
		mctx[1].options = 0;
#endif

		r = memc_init_ctx_mirror (mctx, 2);
		copy_alive (selected, mctx);
		if (r == -1) {
			msg_err ("check_greylisting: cannot connect to memcached upstream: %s", inet_ntoa (selected->addr[0]));
			upstream_fail (&selected->up, tm.tv_sec);
			return GREY_ERROR;
		}
		r = memc_get_mirror (mctx, 2, &cur_param, &s);
		copy_alive (selected, mctx);
		/* Greylisting record does not exist, writing new one */
		if (r == NOT_EXISTS) {
			c = cur_param.key;
			s = sizeof (cur_param.key);
			if (cfg->white_prefix) {
				s = strlcpy (c, cfg->white_prefix, s);
				c += s;
			}
			if (sizeof (cur_param.key) - s > sizeof (md5_out)) {
				memcpy (c, md5_out, sizeof (md5_out));
			}
			else {
				msg_warn ("check_greylisting: white_prefix(%s) too long for memcached key, error in configure", cfg->white_prefix);
				memcpy (cur_param.key, md5_out, sizeof (md5_out));
			}
			s = 1;
			/* Write record to memcached */
			cur_param.buf = (u_char *)&tm;
			cur_param.bufsize = sizeof (tm);
			r = memc_set_mirror (mctx, 2, &cur_param, &s, cfg->greylisting_expire);
			msg_debug ("check_greylisting: write hash to grey list from: %s@%s to: %s, md5: %s, time: %ld.%ld", priv->priv_from, 
							priv->priv_ip, priv->priv_rcpt, cur_param.key, (long int)tm.tv_sec, (long int)tm.tv_usec);
			copy_alive (selected, mctx);
			if (r == OK) {
				upstream_ok (&selected->up, tm.tv_sec);
				memc_close_ctx_mirror (mctx, 2);
				return GREY_GREYLISTED;
			}
			else {
				memc_close_ctx_mirror (mctx, 2);
				msg_info ("check_greylisting: cannot write to memcached: %s", memc_strerror (r));
			}
		}	
		/* Greylisting record exists, checking time */
		else if (r == OK) {
			if (tm.tv_sec - tm1.tv_sec < cfg->greylisting_timeout) {
				/* Client comes too early */
				memc_close_ctx_mirror (mctx, 2);
				upstream_ok (&selected->up, tm.tv_sec);
				return GREY_GREYLISTED;
			}
			else {
				/* Write to whitelist memcached server */
				selected = (struct memcached_server *) get_upstream_by_hash ((void *)cfg->memcached_servers_white,
									cfg->memcached_servers_white_num, sizeof (struct memcached_server),
									(time_t)tm.tv_sec, cfg->memcached_error_time, cfg->memcached_dead_time, cfg->memcached_maxerrors,
									(char *)final, MD5_SIZE);
				if (selected == NULL) {
					if (cfg->memcached_servers_white_num != 0) {
						msg_warn ("check_greylisting: cannot get memcached upstream for whitelisting");
					}
				}
				else {
					mctx_white[0].protocol = cfg->memcached_protocol;
					memcpy(&mctx_white[0].addr, &selected->addr[0], sizeof (struct in_addr));
					mctx_white[0].port = selected->port[0];
					mctx_white[0].timeout = cfg->memcached_connect_timeout;
					mctx_white[0].alive = selected->alive[0];
					if (selected->num == 2) {
						mctx_white[1].protocol = cfg->memcached_protocol;
						memcpy(&mctx_white[1].addr, &selected->addr[1], sizeof (struct in_addr));
						mctx_white[1].port = selected->port[1];
						mctx_white[1].timeout = cfg->memcached_connect_timeout;
						mctx_white[1].alive = selected->alive[0];
					}
					else {
						mctx_white[1].alive = 0;
					}
					/* Reviving upstreams if all are dead */
					if (mctx_white[0].alive == 0 && mctx_white[1].alive == 0) {
						mctx_white[0].alive = 1;
						mctx_white[1].alive = 1;
						copy_alive (selected, mctx_white);
					}
#ifdef WITH_DEBUG
					mctx_white[0].options = MEMC_OPT_DEBUG;
					mctx_white[1].options = MEMC_OPT_DEBUG;
#else
					mctx_white[0].options = 0;
					mctx_white[1].options = 0;
#endif
					r = memc_init_ctx_mirror (mctx_white, 2);
					copy_alive (selected, mctx_white);
					if (r == -1) {
						msg_warn ("check_greylisting: cannot connect to memcached whitelist upstream: %s", inet_ntoa (selected->addr[0]));
						upstream_fail (&selected->up, tm.tv_sec);
					}
					else {
						s = 1;
						cur_param.buf = (u_char *)&tm;
           				cur_param.bufsize = sizeof (tm);
						r = memc_set_mirror (mctx_white, 2, &cur_param, &s, cfg->whitelisting_expire);
						copy_alive (selected, mctx_white);
						if (r == OK) {
							msg_debug ("check_greylisting: write hash to white list from: %s@%s to: %s, md5: %s, time: %ld.%ld", priv->priv_from, 
								priv->priv_ip, priv->priv_rcpt, md5_out, (long int)tm.tv_sec, (long int)tm.tv_usec);
							memc_close_ctx_mirror (mctx_white, 2);
							upstream_ok (&selected->up, tm.tv_sec);
						}
						else {
							msg_info ("check_greylisting: cannot write to memcached(%s): %s", inet_ntoa (selected->addr[0]), memc_strerror (r));
							memc_close_ctx_mirror (mctx_white, 2);
							upstream_fail (&selected->up, tm.tv_sec);
						}
						memc_close_ctx_mirror (mctx_white, 2);
					}
				}
			}
		}
		/* Error getting greylisting record */
		else {
				upstream_fail (&selected->up, tm.tv_sec);
		}
		memc_close_ctx_mirror (mctx, 2);
	}

	return GREY_WHITELISTED;
}

/* Milter callbacks */

static sfsistat 
mlfi_connect(SMFICTX * ctx, char *hostname, _SOCK_ADDR * addr)
{
    struct mlfi_priv *priv;

    priv = malloc(sizeof (struct mlfi_priv));

    if (priv == NULL) {
		return SMFIS_TEMPFAIL;
    }
    memset(priv, '\0', sizeof (struct mlfi_priv));
	priv->strict = 1;
	priv->serial = cfg->serial;

	priv->priv_rcptcount = 0;

	if (gettimeofday (&priv->conn_tm, NULL) == -1) {
		msg_err ("Internal error: gettimeofday failed %m");
		return SMFIS_TEMPFAIL;
	}

    smfi_setpriv(ctx, priv);
	/* Cannot set reply here, so delay processing of connect stage */
	return SMFIS_CONTINUE;
}

static sfsistat
mlfi_helo(SMFICTX *ctx, char *helostr)
{
	struct mlfi_priv *priv;

	priv = (struct mlfi_priv *) smfi_getpriv (ctx);

	strlcpy (priv->priv_helo, helostr, ADDRLEN);
	msg_debug ("mlfi_helo: got helo value: %s", priv->priv_helo);
	
	return SMFIS_CONTINUE;
}

static sfsistat
mlfi_envfrom(SMFICTX *ctx, char **envfrom)
{
	char *tmpfrom;
	struct mlfi_priv *priv;
	struct rule *act;
	int i;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

	/*
	 * Get mail from addr
	 */
    tmpfrom = smfi_getsymval(ctx, "{mail_addr}");
    if (tmpfrom == NULL || *tmpfrom == '\0') {
		tmpfrom = "<>";
	}
	for (i = 0; i < sizeof(priv->priv_from) - 1; i++) {
		priv->priv_from[i] = tolower (*tmpfrom++);
		if (*tmpfrom == '\0') {
			i++;
			break;
		}
	}
	priv->priv_from[i] = '\0';
	msg_debug ("mlfi_envfrom: got from value: %s", priv->priv_from);

	/* Extract IP and hostname */
	tmpfrom = smfi_getsymval(ctx, "{client_addr}");
	if (tmpfrom != NULL) {
		strlcpy (priv->priv_ip, tmpfrom, sizeof (priv->priv_ip));
		inet_aton (priv->priv_ip, &priv->priv_addr.sin_addr);
		msg_debug ("mlfi_envfrom: got ip value: %s", priv->priv_ip);
		priv->priv_addr.sin_family = AF_INET;
	}
	tmpfrom = smfi_getsymval(ctx, "{client_name}");
	if (tmpfrom != NULL) {
		strlcpy (priv->priv_hostname, tmpfrom, sizeof (priv->priv_hostname));
		msg_debug ("mlfi_envfrom: got host value: %s", priv->priv_hostname);
	}
	else {
		strlcpy (priv->priv_hostname, "unknown", sizeof (priv->priv_hostname));
	}

#ifndef STRICT_AUTH
	tmpfrom = smfi_getsymval(ctx, "{auth_authen}");
	if (tmpfrom != NULL) {
		priv->strict = 0;
		msg_info ("mlfi_envfrom: turn off strict checks for authenticated sender: %s", tmpfrom);
	}
#endif

	CFG_RLOCK();
	/* Check connect */
	act = regexp_check (cfg, priv, STAGE_CONNECT);
	if (act != NULL) {
		priv->matched_rules[STAGE_CONNECT] = act;
	}
	/* Check helo */
	act = regexp_check (cfg, priv, STAGE_HELO);
	if (act != NULL) {
		priv->matched_rules[STAGE_HELO] = act;
	}
	
	/* Check envfrom */
	act = regexp_check (cfg, priv, STAGE_ENVFROM);
	if (act != NULL) {
		priv->matched_rules[STAGE_ENVFROM] = act;
	}

	CFG_UNLOCK();
	return SMFIS_CONTINUE;
}

static sfsistat
mlfi_envrcpt(SMFICTX *ctx, char **envrcpt)
{
	struct mlfi_priv *priv;
	struct rule *act;
	char *tmprcpt;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}
	/*
	 * Get recipient address
	 */
    tmprcpt = *envrcpt;
    if (tmprcpt == NULL || *tmprcpt == '\0') {
		tmprcpt = "<>";
	}
	/* Copy first recipient to priv - this is needed for dcc checking and ratelimits */
	strlcpy (priv->priv_rcpt, tmprcpt, sizeof (priv->priv_rcpt));
	msg_debug ("mlfi_envrcpt: got rcpt value: %s", priv->priv_rcpt);
	CFG_RLOCK();
	/* Check ratelimit */
	if (rate_check (priv, cfg, 0) == 0) {
		/* Rate is more than limit */
		if (smfi_setreply (ctx, RCODE_TEMPFAIL, XCODE_TEMPFAIL, (char *)"Rate limit exceeded") != MI_SUCCESS) {
			msg_err("smfi_setreply");
		}
		CFG_UNLOCK();
	    (void)mlfi_cleanup (ctx, false);
		return SMFIS_TEMPFAIL;
	}
	/* Check recipient */
	act = regexp_check (cfg, priv, STAGE_ENVRCPT);
	if (act != NULL) {
		priv->matched_rules[STAGE_ENVRCPT] = act;
	}

	CFG_UNLOCK();
	return SMFIS_CONTINUE;
}

static sfsistat
mlfi_data(SMFICTX *ctx)
{
    struct mlfi_priv *priv;
	int r;
	char *id;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

    /* set queue id */
    id = smfi_getsymval(ctx, "i");

	CFG_RLOCK();
	if (id) {
    	strlcpy (priv->mlfi_id, id, sizeof(priv->mlfi_id));
	}
	else {
		strlcpy (priv->mlfi_id, "NOQUEUE", sizeof (priv->mlfi_id));
		msg_info ("mlfi_data: cannot get queue id, set to 'NOQUEUE'");
	}

	if (priv->priv_ip[0] != '\0' && *priv->priv_rcpt != '\0' && cfg->memcached_servers_grey_num > 0 &&
		cfg->greylisting_timeout > 0 && cfg->greylisting_expire > 0 && priv->strict != 0) {

		msg_debug ("mlfi_data: %s: checking greylisting", priv->mlfi_id);
		r = check_greylisting (priv);
		switch (r) {
			case GREY_GREYLISTED:
				if (smfi_setreply (ctx, RCODE_LATER, XCODE_TEMPFAIL, (char *)"Try again later") != MI_SUCCESS) {
					msg_err("mlfi_data: %s: smfi_setreply failed", priv->mlfi_id);
				}
				CFG_UNLOCK();
				(void)mlfi_cleanup (ctx, false);
				return SMFIS_TEMPFAIL;
				break;
			case GREY_ERROR:
				if (smfi_setreply (ctx, RCODE_TEMPFAIL, XCODE_TEMPFAIL, (char *)"Service unavailable") != MI_SUCCESS) {
					msg_err("mlfi_data: %s: smfi_setreply failed", priv->mlfi_id);
				}
				CFG_UNLOCK();
				(void)mlfi_cleanup (ctx, false);
				break;
			case GREY_WHITELISTED:
			default:
				break;
		}
	}

	CFG_UNLOCK();
	return SMFIS_CONTINUE;
}

static sfsistat 
mlfi_header(SMFICTX * ctx, char *headerf, char *headerv)
{
    struct mlfi_priv *priv;
#ifdef HAVE_PATH_MAX
	char buf[PATH_MAX];
#elif defined(HAVE_MAXPATHLEN)
	char buf[MAXPATHLEN];
#else
#error "neither PATH_MAX nor MAXPATHEN defined"
#endif
    int fd;
	struct rule *act;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

	if (strncasecmp (headerf, "In-Reply-To", sizeof ("In-Reply-To") - 1) == 0) {
		check_message_id (priv, headerv);
	}
	else if (strncasecmp (headerf, "Return-Path", sizeof ("Return-Path") - 1) == 0) {
		priv->has_return_path = 1;
	}
    /*
     * Create temporary file, if this is first call of mlfi_header(), and it
     * not yet created
     */

	CFG_RLOCK();
    if (!priv->fileh) {
		snprintf (buf, sizeof (buf), "%s/msg.XXXXXXXX", cfg->temp_dir);
		strlcpy (priv->file, buf, sizeof (priv->file));
		/* mkstemp is based on arc4random (3) and is not reentrable
		 * so acquire mutex for it
		 */
		pthread_mutex_lock (&mkstemp_mtx);
		fd = mkstemp (priv->file);
		pthread_mutex_unlock (&mkstemp_mtx);

		if (fd == -1) {
	    	msg_warn ("mlfi_header: %s: mkstemp failed, %d: %m", priv->mlfi_id, errno);
			CFG_UNLOCK();
	    	(void)mlfi_cleanup (ctx, false);
	    	return SMFIS_TEMPFAIL;
		}
		priv->fileh = fdopen(fd, "w");

		if (!priv->fileh) {
	    	msg_warn ("mlfi_header: %s: can't open tempfile, %d: %m", priv->mlfi_id, errno);
			CFG_UNLOCK();
	    	(void)mlfi_cleanup(ctx, false);
	    	return SMFIS_TEMPFAIL;
		}
		fprintf (priv->fileh, "Received: from %s (%s [%s]) by localhost (Postfix) with ESMTP id 0000000;\n",
				 priv->priv_helo, priv->priv_hostname, priv->priv_ip); 
    }

    /*
     * Write header line to temporary file.
     */

    fprintf (priv->fileh, "%s: %s\n", headerf, headerv);
	/* Check header with regexp */
	priv->priv_cur_header.header_name = headerf;
	priv->priv_cur_header.header_value = headerv;
	act = regexp_check (cfg, priv, STAGE_HEADER);
	if (act != NULL) {
		priv->matched_rules[STAGE_HEADER] = act;
	}

	CFG_UNLOCK();
    return SMFIS_CONTINUE;
}

static sfsistat 
mlfi_eoh(SMFICTX * ctx)
{
    struct mlfi_priv *priv;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		(void)mlfi_cleanup (ctx, false);
		return SMFIS_TEMPFAIL;
	}
	
	if (!priv->has_return_path) {
		fprintf (priv->fileh, "Return-Path: <%s>\r\n", priv->priv_from);
	}
    fprintf (priv->fileh, "\r\n");
    return SMFIS_CONTINUE;
}

static sfsistat 
mlfi_eom(SMFICTX * ctx)
{
    struct mlfi_priv *priv;
    int r;
	double spamd_marks[2];
#ifdef HAVE_PATH_MAX
	char strres[PATH_MAX], buf[PATH_MAX];
#elif defined(HAVE_MAXPATHLEN)
	char strres[MAXPATHLEN], buf[MAXPATHLEN ];
#else
#error "neither PATH_MAX nor MAXPATHEN defined"
#endif
    char *id;
    struct stat sb;
	struct action *act;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		(void)mlfi_cleanup (ctx, false);
		return SMFIS_TEMPFAIL;
	}
	
	/* set queue id */
    id = smfi_getsymval(ctx, "i");

	if (id) {
    	strlcpy (priv->mlfi_id, id, sizeof(priv->mlfi_id));
	}
	else {
		strlcpy (priv->mlfi_id, "NOQUEUE", sizeof (priv->mlfi_id));
		msg_info ("mlfi_eom: cannot get queue id, set to 'NOQUEUE'");
	}

	CFG_RLOCK();
	
	if (cfg->serial == priv->serial) {
		msg_debug ("mlfi_eom: %s: checking regexp rules", priv->mlfi_id);
		act = rules_check (priv->matched_rules);
		if (act != NULL && act->type != ACTION_ACCEPT) {
			CFG_UNLOCK ();
			(void)mlfi_cleanup (ctx, false);
			return set_reply (ctx, act);
		}
	}
	else {
		msg_warn ("mlfi_eom: %s: config was reloaded, not checking rules", priv->mlfi_id);
	}
	/*
	 * Is the sender address SPF-compliant?
	 */
	if (cfg->spf_domains_num > 0) {
		msg_debug ("mlfi_eom: %s: check spf", priv->mlfi_id);
		r = spf_check (priv, cfg);
		switch (r) {
			case SPF_RESULT_PASS:
			case SPF_RESULT_SOFTFAIL:
			case SPF_RESULT_NEUTRAL:
			case SPF_RESULT_NONE:
				break;
			case SPF_RESULT_FAIL:
				if (*priv->priv_rcpt != '\0' && !is_whitelisted_rcpt (priv->priv_rcpt)) {
	    			snprintf (buf, sizeof (buf) - 1, "SPF policy violation. Host %s[%s] is not allowed to send mail as %s.",
							(*priv->priv_hostname != '\0') ? priv->priv_hostname : "unresolved",
							priv->priv_ip, priv->priv_from);
	    			smfi_setreply (ctx, RCODE_REJECT, XCODE_REJECT, buf);
					CFG_UNLOCK();
					(void)mlfi_cleanup (ctx, false);
					return SMFIS_REJECT;
				}
				break;
		}
	}

    fflush (priv->fileh);

    /* check file size */
    if (stat (priv->file, &sb) == -1) {
		msg_warn ("mlfi_eom: %s: stat failed: %m", priv->mlfi_id);
		CFG_UNLOCK();
		return mlfi_cleanup (ctx, true);
	}
    else if (cfg->sizelimit != 0 && sb.st_size > cfg->sizelimit) {
		msg_warn ("mlfi_eom: %s: message size(%zd) exceeds limit(%zd), not scanned, %s", priv->mlfi_id, (size_t)sb.st_size, cfg->sizelimit, priv->file);
		CFG_UNLOCK();
		return mlfi_cleanup (ctx, true);
	}
    msg_warn ("mlfi_eom: %s: tempfile=%s, size=%lu", priv->mlfi_id, priv->file, (unsigned long int)sb.st_size);
	
	if (!priv->strict) {
		msg_info ("mlfi_eom: %s: from %s[%s] from=<%s> to=<%s> is reply to our message %s; skip greylist, dcc, spamd", priv->mlfi_id, 
				priv->priv_hostname, priv->priv_ip, priv->priv_from, priv->priv_rcpt, priv->reply_id);
	}

#ifdef HAVE_DCC
 	/* Check dcc */
	if (cfg->use_dcc == 1 && !is_whitelisted_rcpt (priv->priv_rcpt) && priv->strict) {
		msg_debug ("mlfi_eom: %s: check dcc", priv->mlfi_id);
		r = check_dcc (priv);
		switch (r) {
			case 'A':
				break;
			case 'G':
				msg_warn ("mlfi_eom: %s: greylisting by dcc", priv->mlfi_id);
				smfi_setreply (ctx, RCODE_LATER, XCODE_TEMPFAIL, "Try again later");
				CFG_UNLOCK();
				mlfi_cleanup (ctx, false);
				return SMFIS_TEMPFAIL;
			case 'R':
				msg_warn ("mlfi_eom: %s: rejected by dcc", priv->mlfi_id);
				smfi_setreply (ctx, "550", XCODE_REJECT, "Message content rejected");
				CFG_UNLOCK();
				mlfi_cleanup (ctx, false);
				return SMFIS_REJECT;
			case 'S': /* XXX - dcc selective reject - not implemented yet */
			case 'T': /* Temp failure by dcc */
			default:
				break;
		}
	}
#endif
	
	/* Check clamav */
	if (cfg->clamav_servers_num != 0) {
		msg_debug ("mlfi_eom: %s: check clamav", priv->mlfi_id);
	    r = check_clamscan (priv->file, strres, sizeof (strres));
    	if (r < 0) {
			msg_warn ("mlfi_eom: %s: check_clamscan() failed, %d", priv->mlfi_id, r);
			CFG_UNLOCK();
			(void)mlfi_cleanup (ctx, false);
			return SMFIS_TEMPFAIL;
    	}
    	if (*strres) {
			msg_warn ("mlfi_eom: %s: rejecting virus %s", priv->mlfi_id, strres);
			snprintf (buf, sizeof (buf), "Infected: %s", strres);
			smfi_setreply (ctx, RCODE_REJECT, XCODE_REJECT, buf);
			CFG_UNLOCK();
			mlfi_cleanup (ctx, false);
			return SMFIS_REJECT;
    	}
	}
	/* Check spamd */
	if (cfg->spamd_servers_num != 0 && !is_whitelisted_rcpt (priv->priv_rcpt) && priv->strict
		&& radix32tree_find (cfg->spamd_whitelist, ntohl((uint32_t)priv->priv_addr.sin_addr.s_addr)) == RADIX_NO_VALUE) {
		msg_debug ("mlfi_eom: %s: check spamd", priv->mlfi_id);
		r = spamdscan (priv->file, cfg, spamd_marks);
		if (r < 0) {
			msg_warn ("mlfi_eom: %s: spamdscan() failed, %d", priv->mlfi_id, r);
		}
		else if (r == 1) {
			msg_warn ("mlfi_eom: %s: rejecting spam [%f/%f]", priv->mlfi_id, spamd_marks[0], spamd_marks[1]);
			smfi_setreply (ctx, RCODE_REJECT, XCODE_REJECT, cfg->spamd_reject_message);
			CFG_UNLOCK();
			mlfi_cleanup (ctx, false);
			return SMFIS_REJECT;
		}
	}
	/* Update rate limits for message */
	msg_debug ("mlfi_eom: %s: updating rate limits", priv->mlfi_id);
	rate_check (priv, cfg, 1);

	CFG_UNLOCK();
    return mlfi_cleanup (ctx, true);
}

static sfsistat 
mlfi_close(SMFICTX * ctx)
{
    struct mlfi_priv *priv;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}
	msg_debug ("mlfi_close: cleanup");

    free(priv);
    smfi_setpriv(ctx, NULL);

    return SMFIS_ACCEPT;
}

static sfsistat 
mlfi_abort(SMFICTX * ctx)
{
    return mlfi_cleanup(ctx, false);
}

static sfsistat 
mlfi_cleanup(SMFICTX * ctx, bool ok)
{
    sfsistat rstat = SMFIS_CONTINUE;
    struct mlfi_priv *priv;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}
	msg_debug ("mlfi_cleanup: cleanup");

    if (priv->fileh) {
		if (fclose (priv->fileh) != 0) {
			msg_err ("mlfi_close: %s: close failed (%d), %m", priv->mlfi_id, errno);
		}
		priv->fileh = NULL;
    }
    if (*priv->file) {
		unlink (priv->file);
		priv->file[0] = '\0';
    }
	/* clean message specific data */
	priv->strict = 1;
	priv->mlfi_id[0] = '\0';
	priv->reply_id[0] = '\0';
	priv->priv_from[0] = '\0';
	priv->priv_rcpt[0] = '\0';
	priv->priv_rcptcount = 0;
    /* return status */
    return rstat;
}

static sfsistat 
mlfi_body(SMFICTX * ctx, u_char * bodyp, size_t bodylen)
{
    struct mlfi_priv *priv;
	struct rule *act;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

    if (fwrite (bodyp, bodylen, 1, priv->fileh) != 1) {
		msg_warn ("mlfi_body: %s: file write error, %d: %m", priv->mlfi_id, errno);
		(void)mlfi_cleanup (ctx, false);
		return SMFIS_TEMPFAIL;;
    }
	/* Check body with regexp */
	priv->priv_cur_body.value = (char *)bodyp;
	priv->priv_cur_body.len = bodylen;
	CFG_RLOCK();

	act = regexp_check (cfg, priv, STAGE_BODY);
	if (act != NULL) {
		priv->matched_rules[STAGE_BODY] = act;
	}
    /* continue processing */

	CFG_UNLOCK();
    return SMFIS_CONTINUE;
}


/*****************************************************************************/

/*
 * check_clamscan() return values: 0 	- scanned (or not scanned due to
 * filesize limit) -1	- retry limit exceeded -2	- unexpected error,
 * e.g. unexpected reply from server (suppose scanned message killed
 * clamd...)
 */

static int 
check_clamscan(const char *file, char *strres, size_t strres_len)
{
    int r = -2;

    *strres = '\0';

    /* scan using libclamc clamscan() */
    r = clamscan (file, cfg, strres, strres_len);
 
    /* reset virusname for non-viruses */
    if (*strres && (!strcmp (strres, "Suspected.Zip") || !strcmp (strres, "Oversized.Zip"))) {
		*strres = '\0';
	}

    return r;
}

#ifdef HAVE_DCC
static int
check_dcc (const struct mlfi_priv *priv)
{
	DCC_EMSG emsg;
	char *homedir = 0;
	char opts[] = "";
	DCC_SOCKU sup;
	DCCIF_RCPT *rcpts = NULL, rcpt;
	int	dccres;
	int dccfd, dccofd = -1;

	if (!*priv->file) {
		return 0;
	}

	dccfd = open (priv->file, O_RDONLY);

	if (dccfd == -1) {
		msg_warn ("check_dcc: %s: dcc data file open(): %s", priv->mlfi_id, strerror (errno));
		return 0;
	}

	dcc_mk_su (&sup, AF_INET, &priv->priv_addr.sin_addr, 0);

	rcpt.next = rcpts;
	rcpt.addr = priv->priv_rcpt;
	rcpt.user = "";
	rcpt.ok = '?';
	rcpts = &rcpt;
	
	dccres = dccif (emsg, /*out body fd*/dccofd, /*out_body*/0,
					opts, &sup, priv->priv_hostname, priv->priv_helo,
					(priv->priv_from == 0) || (priv->priv_from[0] == 0) ? "<>" : priv->priv_from,
					rcpts, dccfd, /*in_body*/0, homedir);

	return dccres;
}
#endif

/* 
 * vi:ts=4 
 */
