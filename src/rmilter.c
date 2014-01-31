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

#ifdef WITH_SPF
#include "spf2/spf.h"
#include "spf.h"
#endif


#include "libclamc.h"
#include "libspamd.h"
#include "cfg_file.h"
#include "rmilter.h"
#include "regexp.h"
#ifdef HAVE_DCC
#include "dccif.h"
#endif
#include "ratelimit.h"
#include "greylist.h"
#include "blake2.h"

#ifndef HAVE_STDBOOL_H
#  ifndef bool
#   ifndef __bool_true_false_are_defined
typedef int bool;
#    define __bool_true_false_are_defined   1
#   endif /* ! __bool_true_false_are_defined */
#  endif /* bool */
# ifndef true
#define false	0
#define true	1
# endif				/* ! true */
#endif

#define SPAM_SUBJECT "***SPAM***"

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
static void send_beanstalk (const struct mlfi_priv *);
#ifdef HAVE_DCC
static int check_dcc(const struct mlfi_priv *);
#endif

struct smfiDesc smfilter =
{
		"rmilter",		/* filter name */
		SMFI_VERSION,	/* version code -- do not change */
		SMFIF_ADDHDRS | SMFIF_CHGHDRS | SMFIF_ADDRCPT | SMFIF_DELRCPT,	/* flags */
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
#if (SMFI_PROT_VERSION >= 4)
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
create_temp_file (struct mlfi_priv *priv)
{
#ifdef HAVE_PATH_MAX
	char buf[PATH_MAX];
#elif defined(HAVE_MAXPATHLEN)
	char buf[MAXPATHLEN];
#else
#error "neither PATH_MAX nor MAXPATHEN defined"
#endif
	int fd;

	snprintf (buf, sizeof (buf), "%s/msg.XXXXXXXX", cfg->temp_dir);
	rmilter_strlcpy (priv->file, buf, sizeof (priv->file));
	/* mkstemp is based on arc4random (3) and is not reentrable
	 * so acquire mutex for it
	 */
	pthread_mutex_lock (&mkstemp_mtx);
	fd = mkstemp (priv->file);
	pthread_mutex_unlock (&mkstemp_mtx);

	if (fd == -1) {
		msg_warn ("create_temp_file: %s: mkstemp failed, %d: %m", priv->mlfi_id, errno);
		return -1;
	}
	priv->fileh = fdopen(fd, "w");

	if (!priv->fileh) {
		msg_warn ("create_temp_file: %s: can't open tempfile, %d: %m", priv->mlfi_id, errno);
		return -1;
	}
	fprintf (priv->fileh, "Received: from %s (%s [%s]) by localhost (Postfix) with ESMTP id 0000000;\r\n",
			priv->priv_helo, priv->priv_hostname, priv->priv_ip);

	return 0;
}

static char *
dkim_stripcr (char *str)
{
	char *t, *h;

	for (t = str, h = str; *t != '\0'; t++) {
		if (*t == '\r') {
			continue;
		}

		if (t != h) {
			*h = *t;
		}
		h++;
	}

	if (h != t) {
		*h = *t;
	}

	return str;
}

static void
check_message_id (struct mlfi_priv *priv, char *header) 
{
	blake2b_state mdctx;
	u_char final[BLAKE2B_OUTBYTES], param = '0';
	char md5_out[BLAKE2B_OUTBYTES * 2 + 1], *c, ipout[INET_ADDRSTRLEN + 1];
	struct memcached_server *selected;
	memcached_ctx_t mctx;
	memcached_param_t cur_param;
	int r;
	size_t s = strlen (header);

	/* First of all do regexp check of message to determine special message id */
	if (cfg->special_mid_re) {
		if ((r = pcre_exec (cfg->special_mid_re, NULL, header, s, 0, 0, NULL, 0)) >= 0) {
			priv->complete_to_beanstalk = 1;	
		}
	}

	if (cfg->memcached_servers_id_num == 0) {
		return;
	}

	bzero (&cur_param, sizeof (cur_param));

	cur_param.buf = &param;
	cur_param.bufsize = sizeof (param);

	blake2b_init (&mdctx, BLAKE2B_OUTBYTES);
	/* Check reply message id in memcached */
	/* Make hash from message id */
	blake2b_update (&mdctx, (const u_char *)header, s);
	blake2b_final (&mdctx, final, BLAKE2B_OUTBYTES);

	/* Format md5 output */
	s = sizeof (md5_out);
	for (r = 0; r < BLAKE2B_OUTBYTES; r ++){
		s -= snprintf (md5_out + r * 2, s, "%02x", final[r]);
	}

	c = cur_param.key;
	s = sizeof (cur_param.key);
	if (cfg->id_prefix) {
		s = rmilter_strlcpy (c, cfg->id_prefix, s);
		c += s;
	}
	if (sizeof (cur_param.key) - s > sizeof (md5_out)) {
		memcpy (c, md5_out, sizeof (md5_out));
	}
	else {
		msg_warn ("check_id: id_prefix(%s) too long for memcached key, error in configure", cfg->id_prefix);
		memcpy (c, md5_out, sizeof (cur_param.key) - s);
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
		msg_warn ("mlfi_data: cannot connect to memcached upstream: %s",
				inet_ntop (AF_INET, &selected->addr[0], ipout, sizeof (ipout)));
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
		rmilter_strlcpy (priv->reply_id, header, sizeof (priv->reply_id));
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

static sfsistat
check_greylisting_ctx(SMFICTX *ctx, struct mlfi_priv *priv)
{
	int r;
	void *ptr;
	CFG_RLOCK();

	if (priv->priv_ip[0] != '\0' && cfg->memcached_servers_grey_num > 0 &&
			cfg->greylisting_timeout > 0 && cfg->greylisting_expire > 0 && priv->strict != 0) {

		msg_debug ("mlfi_data: %s: checking greylisting", priv->mlfi_id);
		ptr = priv->priv_addr.family == AF_INET6 ? (void *)&priv->priv_addr.addr.sa6.sin6_addr :
				(void *)&priv->priv_addr.addr.sa4.sin_addr;
		r = check_greylisting (cfg, ptr, priv->priv_addr.family, &priv->conn_tm,
				priv->priv_from, priv->rcpts.lh_first->r_addr);
		switch (r) {
		case GREY_GREYLISTED:
			if (smfi_setreply (ctx, RCODE_LATER, XCODE_TEMPFAIL, cfg->greylisted_message) != MI_SUCCESS) {
				msg_err("mlfi_data: %s: smfi_setreply failed", priv->mlfi_id);
			}
			CFG_UNLOCK();
			return SMFIS_TEMPFAIL;
			break;
		case GREY_ERROR:
			if (smfi_setreply (ctx, RCODE_TEMPFAIL, XCODE_TEMPFAIL, (char *)"Service unavailable") != MI_SUCCESS) {
				msg_err("mlfi_data: %s: smfi_setreply failed", priv->mlfi_id);
			}
			CFG_UNLOCK();
			return SMFIS_TEMPFAIL;
			break;
		case GREY_WHITELISTED:
		default:
			break;
		}
	}
	CFG_UNLOCK();
	return SMFIS_CONTINUE;
}

/* 
 * Send copy of message to beanstalk
 * XXX: too many copy&paste
 */
static void
send_beanstalk_copy (const struct mlfi_priv *priv, struct beanstalk_server *srv)
{
	beanstalk_ctx_t bctx;
	beanstalk_param_t bp;
	size_t s;
	int r, fd;
	void *map;
	struct stat st;
	char ipout[INET_ADDRSTRLEN + 1];

	/* Open and mmap file */
	if (!*priv->file) {
		return;
	}

	if (stat (priv->file, &st) == -1) {
		msg_warn ("send_beanstalk_copy: %s: data file stat(): %s", priv->mlfi_id, strerror (errno));
		return;
	}

	fd = open (priv->file, O_RDONLY);

	if (fd == -1) {
		msg_warn ("send_beanstalk_copy: %s: data file open(): %s", priv->mlfi_id, strerror (errno));
		return;
	}

	if ((map = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		msg_err ("send_beanstalk_copy: cannot mmap file %s, %s", priv->file, strerror (errno));
		close (fd);
		return;
	}

	close (fd);
	bctx.protocol = cfg->beanstalk_protocol;
	memcpy (&bctx.addr, &srv->addr, sizeof (struct in_addr));
	bctx.port = srv->port;
	bctx.timeout = cfg->beanstalk_connect_timeout;

	r = bean_init_ctx (&bctx);
	if (r == -1) {
		munmap (map, st.st_size);
		msg_warn ("send_beanstalk_copy: cannot connect to beanstalk upstream: %s",
				inet_ntop (AF_INET, &srv->addr, ipout, sizeof (ipout)));
		upstream_fail (&srv->up, priv->conn_tm.tv_sec);
		return;
	}

	bp.buf = (u_char *)map;
	bp.bufsize = st.st_size;
	bp.len = bp.bufsize;
	bp.priority = 1025;
	s = 1;

	r = bean_put (&bctx, &bp, &s, cfg->beanstalk_lifetime, 0);

	munmap (map, st.st_size);
	if (r == BEANSTALK_OK) {
		bean_close_ctx (&bctx);
		upstream_ok (&srv->up, priv->conn_tm.tv_sec);
		return;
	}
	else {
		msg_info ("send_beanstalk_copy: cannot put data to beanstalk: %s", bean_strerror (r));
		upstream_fail (&srv->up, priv->conn_tm.tv_sec);
		bean_close_ctx (&bctx);
		return;
	}
	bean_close_ctx (&bctx);

}

static void 
send_beanstalk (const struct mlfi_priv *priv)
{
	struct beanstalk_server *selected;
	beanstalk_ctx_t bctx;
	beanstalk_param_t bp;
	size_t s;
	int r, fd;
	void *map;
	char ipout[INET_ADDRSTRLEN + 1];


	selected = (struct beanstalk_server *) get_random_upstream ((void *)cfg->beanstalk_servers,
			cfg->beanstalk_servers_num, sizeof (struct beanstalk_server),
			priv->conn_tm.tv_sec, cfg->beanstalk_error_time,
			cfg->beanstalk_dead_time, cfg->beanstalk_maxerrors);
	if (selected == NULL) {
		msg_err ("send_beanstalk: upstream get error, %s", priv->file);
		return;
	}

	/* Open and mmap file */
	if (!*priv->file || priv->eoh_pos == 0) {
		return;
	}

	fd = open (priv->file, O_RDONLY);

	if (fd == -1) {
		msg_warn ("send_beanstalk: %s: data file open(): %s", priv->mlfi_id, strerror (errno));
		return;
	}

	if ((map = mmap (NULL, priv->eoh_pos, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		msg_err ("send_beanstalk: cannot mmap file %s, %s", priv->file, strerror (errno));
		close (fd);
		return;
	}

	close (fd);

	bctx.protocol = cfg->beanstalk_protocol;
	memcpy(&bctx.addr, &selected->addr, sizeof (struct in_addr));
	bctx.port = selected->port;
	bctx.timeout = cfg->beanstalk_connect_timeout;

	r = bean_init_ctx (&bctx);
	if (r == -1) {
		msg_warn ("send_beanstalk: cannot connect to beanstalk upstream: %s",
				inet_ntop (AF_INET, &selected->addr, ipout, sizeof (ipout)));
		upstream_fail (&selected->up, priv->conn_tm.tv_sec);
		munmap (map, priv->eoh_pos);
		return;
	}

	bp.buf = (u_char *)map;
	bp.bufsize = priv->eoh_pos;
	bp.len = bp.bufsize;
	bp.priority = 1025;
	s = 1;

	r = bean_put (&bctx, &bp, &s, cfg->beanstalk_lifetime, 0);

	munmap (map, priv->eoh_pos);
	if (r == BEANSTALK_OK) {
		bean_close_ctx (&bctx);
		upstream_ok (&selected->up, priv->conn_tm.tv_sec);
		return;
	}
	else {
		msg_info ("send_beanstalk: cannot put data to beanstalk: %s", bean_strerror (r));
		upstream_fail (&selected->up, priv->conn_tm.tv_sec);
		bean_close_ctx (&bctx);
		return;
	}
	bean_close_ctx (&bctx);

}

static void
format_spamd_reply (char *result, size_t len, char *format, char *symbols)
{
	char *pos = result, *s = format;

	while (pos - result < len && *s != '\0') {
		if (*s != '%') {
			/* Copy next symbol */
			*pos ++ = *s ++;
		}
		else if (*(s + 1) == 's') {
			/* Paste symbols */
			if (symbols != NULL) {
				pos += rmilter_strlcpy (pos, symbols, len - (pos - result));
			}
			else {
				pos += rmilter_strlcpy (pos, "no symbols", len - (pos - result));
			}
		}
	}
	*pos = '\0';
}

/* Milter callbacks */

static sfsistat 
mlfi_connect(SMFICTX * ctx, char *hostname, _SOCK_ADDR * addr)
{
	struct mlfi_priv *priv;
	union sockaddr_un {
		struct sockaddr_in sa4;
		struct sockaddr_in6 sa6;
		struct sockaddr sa;
	} *addr_storage;

	priv = malloc(sizeof (struct mlfi_priv));

	if (priv == NULL) {
		return SMFIS_TEMPFAIL;
	}
	memset(priv, '\0', sizeof (struct mlfi_priv));
	LIST_INIT (&priv->rcpts);
	priv->strict = 1;
	priv->serial = cfg->serial;
	priv->priv_addr.family = AF_UNSPEC;

	priv->priv_rcptcount = 0;

	if (gettimeofday (&priv->conn_tm, NULL) == -1) {
		msg_err ("Internal error: gettimeofday failed %m");
		return SMFIS_TEMPFAIL;
	}

	if (addr != NULL) {
		addr_storage = (union sockaddr_un *)addr;
		priv->priv_addr.family = addr->sa_family;
		switch (addr->sa_family) {
		case AF_INET:
			inet_ntop (AF_INET, &addr_storage->sa4.sin_addr, priv->priv_ip, sizeof (priv->priv_ip));
			memcpy (&priv->priv_addr.addr.sa4, &addr_storage->sa4, sizeof (struct sockaddr_in));
			break;
		case AF_INET6:
			inet_ntop (AF_INET6, &addr_storage->sa6.sin6_addr, priv->priv_ip, sizeof (priv->priv_ip));
			memcpy (&priv->priv_addr.addr.sa6, &addr_storage->sa6, sizeof (struct sockaddr_in6));
			break;
		default:
			rmilter_strlcpy (priv->priv_ip, "NULL", sizeof(priv->priv_ip));
			memcpy (&priv->priv_addr.addr.sa, &addr_storage->sa, sizeof (struct sockaddr));
			break;
		}
	}

	if (hostname != NULL) {
		rmilter_strlcpy (priv->priv_hostname, hostname, sizeof (priv->priv_hostname));
	}
	else {
		priv->priv_hostname[0] = '\0';
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

	rmilter_strlcpy (priv->priv_helo, helostr, ADDRLEN);
	msg_debug ("mlfi_helo: got helo value: %s", priv->priv_helo);

	return SMFIS_CONTINUE;
}

#ifdef WITH_DKIM
static DKIM*
try_wildcard_dkim (const char *domain, struct mlfi_priv *priv)
{
	DKIM_STAT statp;
	struct dkim_domain_entry *dkim_domain;
	DKIM *d;
	int fd;
	struct stat st;
	void *keymap;
#ifdef HAVE_PATH_MAX
	char fname[PATH_MAX + 10];
#elif defined(HAVE_MAXPATHLEN)
	char fname[MAXPATHLEN + 10];
#else
#error "neither PATH_MAX nor MAXPATHEN defined"
#endif

	for(dkim_domain = cfg->dkim_domains; dkim_domain != NULL; dkim_domain = dkim_domain->hh.next) {
		if (dkim_domain->is_wildcard) {
			/* Check for domain */
			if (strcmp (dkim_domain->domain, "*") != 0 && strcasestr (domain, dkim_domain->domain) == NULL) {
				/* Not our domain */
				continue;
			}
			/* Check for directory */
			if (dkim_domain->keyfile) {
				if (stat (dkim_domain->keyfile, &st) != -1 && S_ISDIR (st.st_mode)) {
					/* Print keyfilename in format <dkim_domain>/<domain>.<selector>.key */
					snprintf (fname, sizeof (fname), "%s/%s.%s.key", dkim_domain->keyfile, domain, dkim_domain->selector);
					if (stat (fname, &st) != -1 && S_ISREG (st.st_mode)) {
						fd = open (fname, O_RDONLY);
						if (fd != -1) {
							/* Mmap key */
							keymap = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
							close (fd);
							if (keymap != MAP_FAILED) {
								d = dkim_sign (cfg->dkim_lib,  (u_char *)"rmilter", NULL,
										(u_char *)keymap,  (u_char *)dkim_domain->selector,
										(u_char *)domain,
										cfg->dkim_relaxed_header ? DKIM_CANON_RELAXED : DKIM_CANON_SIMPLE,
										cfg->dkim_relaxed_body ? DKIM_CANON_RELAXED : DKIM_CANON_SIMPLE,
										cfg->dkim_sign_sha256 ? DKIM_SIGN_RSASHA256 : DKIM_SIGN_RSASHA1, -1, &statp);
								/* It is safe to unmap memory here */
								munmap (keymap, st.st_size);
								if (statp != DKIM_STAT_OK) {
									msg_info ("dkim sign failed: %s", dkim_geterror (d));
									if (d) {
										dkim_free (d);
									}
									return NULL;
								}
								else {
									priv->dkim_domain = dkim_domain;
									return d;
								}
							}
						}
					}
				}
			}
		}
	}

	return NULL;
}
#endif

static sfsistat
mlfi_envfrom(SMFICTX *ctx, char **envfrom)
{
	char *tmpfrom, *domain_pos;
	struct mlfi_priv *priv;
	struct rule *act;
	unsigned int i;

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

	if (priv->priv_hostname[0] == '\0') {
		tmpfrom = smfi_getsymval(ctx, "{client_name}");
		if (tmpfrom != NULL) {
			rmilter_strlcpy (priv->priv_hostname, tmpfrom, sizeof (priv->priv_hostname));
			msg_debug ("mlfi_envfrom: got host value: %s", priv->priv_hostname);
		}
		else {
			rmilter_strlcpy (priv->priv_hostname, "unknown", sizeof (priv->priv_hostname));
		}
	}


	tmpfrom = smfi_getsymval(ctx, "{auth_authen}");
	if (tmpfrom != NULL) {
#ifndef STRICT_AUTH
		if (!cfg->strict_auth) {
			msg_info ("mlfi_envfrom: turn off strict checks for authenticated sender: %s", tmpfrom);
			priv->strict = 0;
		}
#endif
		rmilter_strlcpy (priv->priv_user, tmpfrom, sizeof (priv->priv_user));
	}

	/* Check whether we need to sign this message */
#ifdef WITH_DKIM
	CFG_RLOCK();
	DKIM_STAT statp;
	struct dkim_domain_entry *dkim_domain;

	domain_pos = strchr (priv->priv_from, '@');
	if (domain_pos) {
		if (priv->priv_from[i - 1] == '>') {
			priv->priv_from[i - 1] = '\0';
			HASH_FIND_STR (cfg->dkim_domains, domain_pos + 1, dkim_domain, strncasecmp);
			priv->priv_from[i - 1] = '>';
		}
		else {
			HASH_FIND_STR (cfg->dkim_domains, domain_pos + 1, dkim_domain, strncasecmp);
		}
		if (!cfg->dkim_auth_only || *priv->priv_user != '\0') {
			if (dkim_domain && dkim_domain->is_loaded) {
				priv->dkim = dkim_sign (cfg->dkim_lib,  (u_char *)"rmilter", NULL,
						(u_char *)dkim_domain->key,  (u_char *)dkim_domain->selector,
						(u_char *)dkim_domain->domain,
						cfg->dkim_relaxed_header ? DKIM_CANON_RELAXED : DKIM_CANON_SIMPLE,
								cfg->dkim_relaxed_body ? DKIM_CANON_RELAXED : DKIM_CANON_SIMPLE,
										cfg->dkim_sign_sha256 ? DKIM_SIGN_RSASHA256 : DKIM_SIGN_RSASHA1, -1, &statp);
				if (statp != DKIM_STAT_OK) {
					msg_info ("dkim sign failed: %s", dkim_geterror (priv->dkim));
					if (priv->dkim) {
						dkim_free (priv->dkim);
					}
					priv->dkim = NULL;
				}
				else {
					msg_debug ("try to add signature for %s domain", dkim_domain->domain);
					priv->dkim_domain = dkim_domain;
				}
			}
			else {
				priv->dkim = try_wildcard_dkim (domain_pos + 1, priv);
				if (priv->dkim) {
					msg_debug ("try to add signature for %s domain", domain_pos + 1);
				}
			}
		}
		else {
			priv->dkim = NULL;
			msg_debug ("do not add dkim signature for unauthorized user");
		}
	}
	CFG_UNLOCK();
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
	struct rcpt *newrcpt;
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
	newrcpt = malloc (sizeof (struct rcpt));
	if (newrcpt == NULL) {
		msg_err ("malloc failed: %s", strerror (errno));
		return SMFIS_TEMPFAIL;
	}
	rmilter_strlcpy (newrcpt->r_addr, tmprcpt, sizeof (newrcpt->r_addr));

	CFG_RLOCK();

	newrcpt->is_whitelisted = is_whitelisted_rcpt (cfg, newrcpt->r_addr, 1);
	if (!newrcpt->is_whitelisted && priv->has_whitelisted) {
		priv->has_whitelisted = 0;
	}
	else if (newrcpt->is_whitelisted && !priv->has_whitelisted) {
		priv->has_whitelisted = 1;
	}
	/* Check ratelimit */
	if (rate_check (priv, cfg, newrcpt->r_addr, 0) == 0) {
		/* Rate is more than limit */
		if (smfi_setreply (ctx, RCODE_TEMPFAIL, XCODE_TEMPFAIL, (char *)"Rate limit exceeded") != MI_SUCCESS) {
			msg_err("smfi_setreply");
		}
		CFG_UNLOCK();
		free (newrcpt);
		return SMFIS_TEMPFAIL;
	}
	LIST_INSERT_HEAD (&priv->rcpts, newrcpt, r_list);
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
	char *id;
	int r;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		mlfi_cleanup (ctx, false);
		return SMFIS_TEMPFAIL;
	}

	/* set queue id */
	id = smfi_getsymval(ctx, "i");

	CFG_RLOCK();
	if (id) {
		rmilter_strlcpy (priv->mlfi_id, id, sizeof(priv->mlfi_id));
	}
	else {
		rmilter_strlcpy (priv->mlfi_id, "NOQUEUE", sizeof (priv->mlfi_id));
		msg_info ("mlfi_data: cannot get queue id, set to 'NOQUEUE'");
	}
	CFG_UNLOCK();

	if (!cfg->spamd_greylist) {
		if ((r = check_greylisting_ctx (ctx, priv)) != SMFIS_CONTINUE) {
			msg_info ("mlfi_eom: %s: greylisting message", priv->mlfi_id);
			mlfi_cleanup (ctx, false);
			return r;
		}
	}

	return SMFIS_CONTINUE;
}

static sfsistat 
mlfi_header(SMFICTX * ctx, char *headerf, char *headerv)
{
	struct mlfi_priv *priv;
	struct rule *act;
	int len;
	char *p, *c, t;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		mlfi_cleanup (ctx, false);
		return SMFIS_TEMPFAIL;
	}

	if (headerv && strncasecmp (headerf, "In-Reply-To", sizeof ("In-Reply-To") - 1) == 0) {
		check_message_id (priv, headerv);
	}
	else if (headerv && strncasecmp (headerf, "References", sizeof ("References") - 1) == 0) {
		/* Break references into individual message-id */
		c = headerv;
		p = c;
		while (*p) {
			if (isspace (*p)) {
				t = *p;
				*p = '\0';
				check_message_id (priv, c);
				*p = t;
				while (isspace (*p) &&  *p) {
					p ++;
				}
				c = p;
			}
			p ++;
		}
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
		if (create_temp_file (priv) == -1) {
			msg_err ("mlfi_eoh: cannot create temp file");
			CFG_UNLOCK();
			mlfi_cleanup (ctx, false);
			return SMFIS_TEMPFAIL;
		}
	}

#ifdef WITH_DKIM
	struct dkim_hash_entry *e;
	u_char *tmp;
	int tmplen, r;

	if (priv->dkim) {
		HASH_FIND_STR (cfg->headers, headerf, e, strncasecmp);
		if (e) {
			tmplen = strlen (headerf) + strlen (headerv) + sizeof (": ");
			tmp = malloc (tmplen);
			if (tmp != NULL) {
				snprintf ((char *)tmp, tmplen, "%s: %s", headerf, headerv);
				r = dkim_header (priv->dkim, tmp, tmplen - 1);
				if (r != DKIM_STAT_OK) {
					msg_info ("dkim_header failed: %s", dkim_geterror (priv->dkim));
				}
				free (tmp);
			}
		}
	}
#endif
	/*
	 * Write header line to temporary file.
	 */

	fprintf (priv->fileh, "%s: %s\n", headerf, headerv);
	/* Check header with regexp */
	priv->priv_cur_header.header_name = headerf;
	priv->priv_cur_header.header_value = headerv;
	if (strcasecmp (headerf, "Subject") == 0) {
		len = sizeof (SPAM_SUBJECT) + strlen (headerv);
		priv->priv_subject = malloc (len);
		if (priv->priv_subject) {
			snprintf (priv->priv_subject, len, SPAM_SUBJECT " %s", headerv);
		}
	}
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
	struct rcpt *rcpt;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		mlfi_cleanup (ctx, false);
		return SMFIS_TEMPFAIL;
	}

	if (!priv->fileh) {
		if (create_temp_file (priv) == -1) {
			msg_err ("mlfi_eoh: cannot create temp file");
			mlfi_cleanup (ctx, false);
			return SMFIS_TEMPFAIL;
		}
	}

	if (!priv->has_return_path && priv->fileh) {
		fprintf (priv->fileh, "Return-Path: <%s>\r\n", priv->priv_from);
	}
	if (priv->fileh) {
		LIST_FOREACH (rcpt, &priv->rcpts, r_list) {
			fprintf (priv->fileh, "X-Rcpt-To: %s\r\n", rcpt->r_addr);
		}
		fprintf (priv->fileh, "\r\n");
		priv->eoh_pos = ftell (priv->fileh);
	}
#ifdef WITH_DKIM
	int r;

	if (priv->dkim) {
		r = dkim_eoh (priv->dkim);
		if (r != DKIM_STAT_OK) {
			msg_info ("<%s> dkim_eoh failed: %s", priv->mlfi_id, dkim_geterror (priv->dkim));
		}
	}
#endif

	return SMFIS_CONTINUE;
}

static sfsistat 
mlfi_eom(SMFICTX * ctx)
{
	struct mlfi_priv *priv;
	int r, er;
#ifdef HAVE_PATH_MAX
	char strres[PATH_MAX], buf[PATH_MAX];
#elif defined(HAVE_MAXPATHLEN)
	char strres[MAXPATHLEN], buf[MAXPATHLEN ];
#else
#error "neither PATH_MAX nor MAXPATHEN defined"
#endif
	char *id, *subject = NULL;
	int prob_max;
	double prob_cur;
	struct stat sb;
	struct action *act;
	struct rcpt *rcpt;
	bool ip_whitelisted = false;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

	/* set queue id */
	id = smfi_getsymval(ctx, "i");

	if (id) {
		rmilter_strlcpy (priv->mlfi_id, id, sizeof(priv->mlfi_id));
	}
	else {
		rmilter_strlcpy (priv->mlfi_id, "NOQUEUE", sizeof (priv->mlfi_id));
		msg_info ("mlfi_eom: cannot get queue id, set to 'NOQUEUE'");
	}


#if (SMFI_PROT_VERSION < 4)
	/* Do greylisting here if DATA callback is not available */
	if (!cfg->spamd_greylist) {
		if ((r = check_greylisting_ctx (ctx, priv)) != SMFIS_CONTINUE) {
			msg_info ("mlfi_eom: %s: greylisting message", priv->mlfi_id);
			mlfi_cleanup (ctx, false);
			return r;
		}
	}
#endif

	CFG_RLOCK();
	if (cfg->serial == priv->serial) {
		msg_debug ("mlfi_eom: %s: checking regexp rules", priv->mlfi_id);
		act = rules_check (priv->matched_rules);
		if (act != NULL && act->type != ACTION_ACCEPT) {
			CFG_UNLOCK ();
			return set_reply (ctx, act);
		}
	}
	else {
		msg_warn ("mlfi_eom: %s: config was reloaded, not checking rules", priv->mlfi_id);
	}
#ifdef WITH_SPF
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
			if (!priv->has_whitelisted) {
				snprintf (buf, sizeof (buf) - 1, "SPF policy violation. Host %s[%s] is not allowed to send mail as %s.",
						(*priv->priv_hostname != '\0') ? priv->priv_hostname : "unresolved",
								priv->priv_ip, priv->priv_from);
				smfi_setreply (ctx, RCODE_REJECT, XCODE_REJECT, buf);
				CFG_UNLOCK();
				mlfi_cleanup (ctx, false);
				return SMFIS_REJECT;
			}
			break;
		}
	}
#endif

	if (priv->complete_to_beanstalk) {
		/* Set actual pos to send all message to beanstalk */
		priv->eoh_pos = ftell (priv->fileh);	
	}

	fflush (priv->fileh);

	/* check file size */
	if (stat (priv->file, &sb) == -1) {
		msg_warn ("mlfi_eom: %s: stat failed: %m", priv->mlfi_id);
		CFG_UNLOCK();
		return mlfi_cleanup (ctx, true);
	}
	else if (cfg->sizelimit != 0 && sb.st_size > (off_t)cfg->sizelimit) {
#ifndef FREEBSD_LEGACY
		msg_warn ("mlfi_eom: %s: message size(%zd) exceeds limit(%zd), not scanned, %s", priv->mlfi_id, (size_t)sb.st_size, cfg->sizelimit, priv->file);
#else
		msg_warn ("mlfi_eom: %s: message size(%ld) exceeds limit(%ld), not scanned, %s", priv->mlfi_id, (long int)sb.st_size, (long int)cfg->sizelimit, priv->file);
#endif
		CFG_UNLOCK();
		return mlfi_cleanup (ctx, true);
	}
	msg_info ("mlfi_eom: %s: tempfile=%s, size=%lu", priv->mlfi_id, priv->file, (unsigned long int)sb.st_size);

	if (!priv->strict) {
		msg_info ("mlfi_eom: %s: from %s[%s] from=<%s> to=<%s> is reply to our message %s; skip dcc, spamd", priv->mlfi_id, 
				priv->priv_hostname, priv->priv_ip, priv->priv_from, priv->rcpts.lh_first->r_addr, priv->reply_id);
	}

#ifdef HAVE_DCC
	/* Check dcc */
	if (cfg->use_dcc == 1 && !priv->has_whitelisted && priv->strict &&
			(cfg->strict_auth && *priv->priv_user != '\0')) {
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

	if (priv->priv_addr.family == AF_INET) {
		if (radix32tree_find (cfg->spamd_whitelist,
				ntohl((uint32_t)priv->priv_addr.addr.sa4.sin_addr.s_addr)) != RADIX_NO_VALUE) {
			ip_whitelisted = true;
		}
	}

	/* Check spamd */
	if (cfg->spamd_servers_num != 0 && !priv->has_whitelisted && priv->strict
			&& !ip_whitelisted &&
			(cfg->strict_auth || *priv->priv_user == '\0')) {
		msg_debug ("mlfi_eom: %s: check spamd", priv->mlfi_id);
		r = spamdscan (ctx, priv, cfg, &subject, 0);

		/* Check on extra servers */
		if (cfg->extra_spamd_servers_num != 0) {
			msg_debug ("mlfi_eom: %s: check spamd", priv->mlfi_id);
			er = spamdscan (ctx, priv, cfg, &subject, 1);
			if (er < 0) {
				msg_warn ("mlfi_eom: %s: extra_spamdscan() failed, %d", priv->mlfi_id, r);
			}
			else if (r != er) {
				msg_warn ("mlfi_eom: spamd_extra_scan returned %d and normal scan returned %d", er, r);
				if (cfg->spam_server && cfg->send_beanstalk_extra_diff) {
					send_beanstalk_copy (priv, cfg->spam_server);
				}
			}
		}
		if (r < 0) {
			msg_warn ("mlfi_eom: %s: spamdscan() failed, %d", priv->mlfi_id, r);
		}
		else if (r != METRIC_ACTION_NOACTION) {
			if (cfg->spam_server && cfg->send_beanstalk_spam) {
				send_beanstalk_copy (priv, cfg->spam_server);
			}
			if (! cfg->spamd_soft_fail || r == METRIC_ACTION_REJECT) {
				msg_info ("mlfi_eom: %s: rejecting spam", priv->mlfi_id);
				format_spamd_reply (strres, sizeof (strres), cfg->spamd_reject_message, NULL);
				smfi_setreply (ctx, RCODE_REJECT, XCODE_REJECT, strres);
				CFG_UNLOCK();
				mlfi_cleanup (ctx, false);
				return SMFIS_REJECT;
			}
			else {
				format_spamd_reply (strres, sizeof (strres), cfg->spamd_reject_message, NULL);

				if (r >= METRIC_ACTION_GREYLIST && cfg->spamd_greylist) {
					/* Perform greylisting */
					CFG_UNLOCK();
					if (check_greylisting_ctx (ctx, priv) != SMFIS_CONTINUE) {
						msg_info ("mlfi_eom: %s: greylisting message according to spamd action", priv->mlfi_id);
						mlfi_cleanup (ctx, false);
						return SMFIS_TEMPFAIL;
					}
					CFG_RLOCK();
				}
				if (r == METRIC_ACTION_ADD_HEADER) {
					msg_info ("mlfi_eom: %s: add spam header to message according to spamd action", priv->mlfi_id);
					smfi_chgheader (ctx, cfg->spam_header, 1, cfg->spam_header_value);
				}
				else if (r == METRIC_ACTION_REWRITE_SUBJECT) {
					msg_info ("mlfi_eom: %s: rewriting spam subject and adding spam header", priv->mlfi_id);

					smfi_chgheader (ctx, cfg->spam_header, 1, cfg->spam_header_value);
					if (subject == NULL) {
						/* Use own settings */
						if (priv->priv_subject) {
							smfi_chgheader (ctx, "Subject", 1, priv->priv_subject);
						}
						else {
							smfi_chgheader (ctx, "Subject", 1, SPAM_SUBJECT);
						}
					}
					else {
						smfi_chgheader (ctx, "Subject", 1, subject);
						free (subject);
					}
				}
			}
		}
	}

	/* Write message to beanstalk */
	if (cfg->beanstalk_servers_num > 0 && cfg->send_beanstalk_headers) {
		send_beanstalk (priv);
	}
	/* Maybe write its copy */
	if (cfg->copy_server && cfg->send_beanstalk_copy) {
		prob_cur = cfg->beanstalk_copy_prob;
		/* Normalize */
		prob_max = 100;
		while (prob_cur < 1.0) {
			prob_max *= 10;
			prob_cur *= 10;
		}
		if (rand () % prob_max <= prob_cur) {
			send_beanstalk_copy (priv, cfg->copy_server);
		}
	}

	/* Check clamav */
	if (cfg->clamav_servers_num != 0) {
		msg_debug ("mlfi_eom: %s: check clamav", priv->mlfi_id);
		r = check_clamscan (priv->file, strres, sizeof (strres));
		if (r < 0) {
			msg_warn ("mlfi_eom: %s: check_clamscan() failed, %d", priv->mlfi_id, r);
			CFG_UNLOCK();
			mlfi_cleanup (ctx, false);
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

	/* Update rate limits for message */
	msg_debug ("mlfi_eom: %s: updating rate limits", priv->mlfi_id);


#if 0
	char rcptbuf[8192];
	int rr = 0;
	for (rcpt = priv->rcpts.lh_first; rcpt != NULL; rcpt = rcpt->r_list.le_next) {
		rate_check (priv, cfg, rcpt->r_addr, 1);
		if (rcpt->r_list.le_next) {
			rr += snprintf (rcptbuf + rr, sizeof (rcptbuf) - rr, "%s, ", rcpt->r_addr);
		}
		else {
			rr += snprintf (rcptbuf + rr, sizeof (rcptbuf) - rr, "%s", rcpt->r_addr);
		}
	}
	smfi_addheader (ctx, "X-Rcpt-To", rcptbuf);
#else
	for (rcpt = priv->rcpts.lh_first; rcpt != NULL; rcpt = rcpt->r_list.le_next) {
		rate_check (priv, cfg, rcpt->r_addr, 1);

	}
#endif
#ifdef WITH_DKIM
	/* Add dkim signature */
	char *hdr;
	size_t len;
	if (priv->dkim) {

		if (!cfg->dkim_fold_header) {
			/* Disable header folding */
			dkim_set_margin (priv->dkim, 0);
		}

		r = dkim_eom (priv->dkim, NULL);
		if (r == DKIM_STAT_OK) {
			r = dkim_getsighdr_d (priv->dkim, 0, (u_char **)&hdr, &len);
			if (r == DKIM_STAT_OK) {
				msg_info ("<%s> d=%s, s=%s, added DKIM signature",
						dkim_getdomain (priv->dkim),
						priv->dkim_domain->selector,
						priv->mlfi_id);
				smfi_addheader (ctx, DKIM_SIGNHEADER, dkim_stripcr (hdr));
			}
			else {
				msg_info ("<%s> d=%s, s=%s, sign failed: %s",
						dkim_getdomain (priv->dkim),
						priv->dkim_domain->selector,
						priv->mlfi_id,
						dkim_geterror (priv->dkim));
			}
		}
		else {
			msg_info ("<%s> d=%s, s=%s, dkim_eom failed: %s",
					dkim_getdomain (priv->dkim),
					priv->dkim_domain->selector,
					priv->mlfi_id,
					dkim_geterror (priv->dkim));
		}
	}
#endif
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

	mlfi_cleanup (ctx, true);

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
	struct rcpt *rcpt, *next;

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
#ifdef WITH_DKIM
	if (priv->dkim) {
		dkim_free (priv->dkim);
	}
	priv->dkim = NULL;
#endif
	if (priv->priv_subject != NULL) {
		free (priv->priv_subject);
		priv->priv_subject = NULL;
	}
	if (ok) {
		/* If ok is not true do not clean SMTP data, just reject message */
		priv->priv_from[0] = '\0';
		priv->priv_user[0] = '\0';
		priv->priv_rcptcount = 0;
		rcpt = priv->rcpts.lh_first;
		while (rcpt) {
			next = rcpt->r_list.le_next;
			free (rcpt);
			rcpt = next;
		}
		LIST_INIT (&priv->rcpts);
	}
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
		mlfi_cleanup (ctx, false);
		return SMFIS_TEMPFAIL;
	}

	if (!priv->fileh) {
		if (create_temp_file (priv) == -1) {
			msg_err ("mlfi_eoh: cannot create temp file");
			mlfi_cleanup (ctx, false);
			return SMFIS_TEMPFAIL;
		}
	}


	if (fwrite (bodyp, bodylen, 1, priv->fileh) != 1) {
		msg_warn ("mlfi_body: %s: file write error, %d: %m", priv->mlfi_id, errno);
		mlfi_cleanup (ctx, false);
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
#ifdef WITH_DKIM
	int r;

	if (priv->dkim) {
		r = dkim_body (priv->dkim, bodyp, bodylen);
		if (r != DKIM_STAT_OK) {
			msg_info ("<%s>: dkim_body failed: %s", priv->mlfi_id, dkim_geterror (priv->dkim));
		}
	}
#endif

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

	dcc_mk_su (&sup, priv->priv_addr.family, &priv->priv_addr.addr.sa, 0);

	rcpt.next = rcpts;
	rcpt.addr = priv->rcpts.lh_first->r_addr;
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
