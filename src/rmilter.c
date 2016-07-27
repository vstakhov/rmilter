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

#include <utlist.h>
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
#include "cache.h"
#ifdef HAVE_DCC
#include "dccif.h"
#endif
#include "ratelimit.h"
#include "greylist.h"
#include "blake2.h"
#include "mfapi.h"

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
static int check_clamscan(void *ctx, struct mlfi_priv *priv, char *, size_t);
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
extern struct rmilter_rng_state *rng_state;

/* Milter mutexes */
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

/*
 * Strip angle braces if needed
 */
static void
normalize_email_addr (const char *src, char *dest, size_t destlen)
{
	const char *c;
	char *d;

	c = src;
	d = dest;

	if (*c == '<') {
		c++;
	}

	while (--destlen != 0) {
		if ((*d++ = tolower (*c++)) == '\0') {
			break;
		}
	}

	if (d > dest + 2 && *(d - 2) == '>') {
		*(d - 2) = '\0';
	}

	if (destlen == 0) {
		*d = '\0';
	}
}

/*
 * xorshift1024*
 * from http://xoroshiro.di.unimi.it/
 */
static uint64_t
prng_next (struct rmilter_rng_state *st)
{
	pthread_mutex_lock (&st->mtx);

	const uint64_t s0 = st->s[st->p];
	uint64_t s1 = st->s[st->p = (st->p + 1) & 15];
	uint64_t res;

	s1 ^= s1 << 31;
	st->s[st->p] = s1 ^ s0 ^ (s1 >> 11) ^ (s0 >> 30);
	res = st->s[st->p] * UINT64_C(1181783497276652981);
	pthread_mutex_unlock (&st->mtx);

	return res;
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
	fd = mkstemp (priv->file);

	if (fd == -1) {
		msg_warn ("create_temp_file: %s: mkstemp failed: %s",
				priv->mlfi_id, strerror (errno));
		return -1;
	}

	/* Set the desired mode */
	fchmod (fd, cfg->tempfiles_mode);

	priv->fileh = fdopen(fd, "w");

	if (!priv->fileh) {
		msg_warn ("create_temp_file: %s: can't open tempfile: %s",
				priv->mlfi_id, strerror (errno));
		return -1;
	}

	fprintf (priv->fileh, "Received: from %s (%s [%s]) by localhost "
			"(Postfix) with ESMTP id %s;\r\n",
			priv->priv_helo, priv->priv_hostname, priv->priv_ip,
			priv->mlfi_id);

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
	u_char final[BLAKE2B_OUTBYTES], *dbuf;
	char md5_out[BLAKE2B_OUTBYTES * 2 + 1], *c, key[MAXKEYLEN];
	int r, keylen;
	size_t s, dlen;

	if (header == NULL) {
		return;
	}

	s = strlen (header);

	/* First of all do regexp check of message to determine special message id */
	if (cfg->special_mid_re) {
		if ((r = pcre_exec (cfg->special_mid_re, NULL, header, s, 0, 0, NULL, 0)) >= 0) {
			priv->complete_to_beanstalk = 1;
		}
	}

	if (cfg->cache_servers_id_num == 0) {
		return;
	}

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

	c = key;
	s = sizeof (key);
	if (cfg->id_prefix) {
		s = rmilter_strlcpy (c, cfg->id_prefix, s);
		c += s;
	}
	if (sizeof (key) - s > sizeof (md5_out)) {
		memcpy (c, md5_out, sizeof (md5_out));
	}
	else {
		msg_warn ("<%s>; check_id: id_prefix(%s) too long for memcached key, error in configure",
			priv->mlfi_id,
			cfg->id_prefix);
		memcpy (c, md5_out, sizeof (key) - s);
	}

	keylen = strlen (key);
	dlen = 1;

	r = rmilter_query_cache(cfg, RMILTER_QUERY_ID, key, keylen, &dbuf, &dlen, priv);
	if (r) {
		free (dbuf);
		/* Turn off strict checks if message id is found */
		priv->strict = 0;
		rmilter_strlcpy (priv->reply_id, header, sizeof (priv->reply_id));
		msg_info ("<%s>; check_message_id: from %s[%s] from=<%s> to=<%s> is reply to our message %s; "
				"skip dcc and spamd checks",
						priv->mlfi_id,
						priv->priv_hostname,
						priv->priv_ip,
						priv->priv_from,
						priv->rcpts->r_addr,
						priv->reply_id);
		return;
	}

}

static sfsistat
check_greylisting_ctx(SMFICTX *ctx, struct mlfi_priv *priv)
{
	int r;
	CFG_RLOCK();

	if (cfg->greylisting_enable &&
			priv->priv_ip[0] != '\0' && cfg->cache_servers_grey_num > 0 &&
			cfg->greylisting_timeout > 0 &&
			cfg->greylisting_expire > 0 && priv->strict != 0) {

		msg_debug ("<%s>; check_greylisting_ctx: checking greylisting", priv->mlfi_id);

		r = check_greylisting (ctx, cfg, priv);
		switch (r) {
		case GREY_GREYLISTED:
			if (smfi_setreply (ctx, RCODE_LATER, XCODE_TEMPFAIL, cfg->greylisted_message) != MI_SUCCESS) {
				msg_err("<%s>; check_greylisting_ctx: smfi_setreply failed", priv->mlfi_id);
			}
			CFG_UNLOCK();
			return SMFIS_TEMPFAIL;
			break;
		case GREY_ERROR:
			if (smfi_setreply (ctx, RCODE_TEMPFAIL, XCODE_TEMPFAIL, (char *)"Service unavailable") != MI_SUCCESS) {
				msg_err("<%s>; check_greylisting_ctx: smfi_setreply failed", priv->mlfi_id);
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

static void
set_random_id (struct mlfi_priv *priv)
{
	uint64_t val;
	static const char hexdigests[16] = "0123456789abcdef";
	const unsigned int nbytes = 5;
	char *buf;
	const char *p;
	unsigned r = 0, i;

	val = prng_next (rng_state);
	val ^= (uint64_t)pthread_self ();

	buf = priv->mlfi_id;

	/* Encode as hex string */
	p = (const char *)&val;

	for (i = 0; i < nbytes; i ++) {
		buf[r++] = hexdigests[(*p >> 4) & 0xF];
		buf[r++] = hexdigests[*p & 0xF];
		p ++;
	}

	buf[r] = '\0';
}

static void
publish_message (struct mlfi_priv *priv, enum rmilter_publish_type type,
		char *extra_buf, size_t extra_len)
{
	const char *channel = NULL;
	void *map;
	size_t sz;
	int ret;

	if (type == RMILTER_PUBLISH_COPY) {
		channel = cfg->cache_copy_channel;
	}
	else {
		channel = cfg->cache_spam_channel;
	}

	if (channel == NULL) {
		return;
	}

	map = rmilter_file_xmap (priv->file, PROT_READ, &sz);

	if (map == NULL) {
		msg_err ("<%s>; cannot read file %s: %s",
						priv->mlfi_id, priv->file, strerror (errno));

		return;
	}

	ret = rmilter_publish_cache (cfg, type, channel, strlen (channel), map, sz,
			priv);

	if (ret == -1) {
		msg_err ("<%s>; cannot publish file %s to stream %s: %s",
				priv->mlfi_id, priv->file, channel, strerror (errno));
		munmap (map, sz);

		return;
	}

	snprintf (extra_buf + strlen (extra_buf), extra_len - strlen (extra_buf),
			"; published to %s (%d clients)", channel, ret);
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
	int port;
	char *mta_host;

	priv = malloc(sizeof (struct mlfi_priv));

	if (priv == NULL) {
		return SMFIS_TEMPFAIL;
	}

	memset(priv, '\0', sizeof (struct mlfi_priv));
	priv->rcpts = NULL;
	priv->strict = 1;
	priv->serial = cfg->serial;
	priv->priv_addr.family = AF_UNSPEC;

	priv->priv_rcptcount = 0;

	if (gettimeofday (&priv->conn_tm, NULL) == -1) {
		msg_err ("Internal error: gettimeofday failed %s", strerror (errno));
		return SMFIS_TEMPFAIL;
	}

	set_random_id (priv);

	if (addr != NULL) {
		addr_storage = (union sockaddr_un *)addr;
		priv->priv_addr.family = addr->sa_family;
		switch (addr->sa_family) {
		case AF_INET:
			inet_ntop (AF_INET, &addr_storage->sa4.sin_addr, priv->priv_ip, sizeof (priv->priv_ip));
			memcpy (&priv->priv_addr.addr.sa4, &addr_storage->sa4, sizeof (struct sockaddr_in));
			port = ntohs (addr_storage->sa4.sin_port);
			break;
		case AF_INET6:
			inet_ntop (AF_INET6, &addr_storage->sa6.sin6_addr, priv->priv_ip, sizeof (priv->priv_ip));
			memcpy (&priv->priv_addr.addr.sa6, &addr_storage->sa6, sizeof (struct sockaddr_in6));
			port = ntohs (addr_storage->sa6.sin6_port);
			break;
		default:
			rmilter_strlcpy (priv->priv_ip, "NULL", sizeof(priv->priv_ip));
			memcpy (&priv->priv_addr.addr.sa, &addr_storage->sa, sizeof (struct sockaddr));
			port = 0;
			break;
		}
	}

	mta_host = smfi_getsymval (ctx, "j");
	if (mta_host == NULL) {
		mta_host = "undefined";
	}

	if (hostname != NULL) {
		rmilter_strlcpy (priv->priv_hostname, hostname, sizeof (priv->priv_hostname));

		msg_info ("<%s>; accepted connection from %s; client: %s:%d (%s)",
				priv->mlfi_id, mta_host,
				priv->priv_ip, port, priv->priv_hostname);
	}
	else {
		priv->priv_hostname[0] = '\0';
		msg_info ("<%s>; accepted connection from %s; client: %s:%d (unknown)",
				priv->mlfi_id, mta_host,
				priv->priv_ip, port);
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
	msg_debug ("<%s>; mlfi_helo: got helo value: %s", priv->mlfi_id, priv->priv_helo);

	return SMFIS_CONTINUE;
}

#ifdef WITH_DKIM
static DKIM*
try_wildcard_dkim (const char *domain, struct mlfi_priv *priv)
{
	DKIM_STAT statp;
	struct dkim_domain_entry *dkim_domain, *tmp;
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

	HASH_ITER (hh, cfg->dkim_domains, dkim_domain, tmp) {
		if (dkim_domain->is_wildcard) {
			/* Check for domain */
			if (strcmp (dkim_domain->domain, "*") != 0 &&
					strstr (domain, dkim_domain->domain) == NULL) {
				/* Not our domain */
				continue;
			}
			/* Check for directory */
			if (dkim_domain->keyfile) {
				if (stat (dkim_domain->keyfile, &st) != -1 && S_ISDIR (st.st_mode)) {
					/* Print keyfilename in format <dkim_domain>/<domain>.<selector>.key */
					snprintf (fname, sizeof (fname), "%s/%s.%s.key",
							dkim_domain->keyfile,
							domain,
							dkim_domain->selector);

					if (stat (fname, &st) != -1 && S_ISREG (st.st_mode)) {
						fd = open (fname, O_RDONLY);

						if (fd != -1) {
							/* Mmap key */
							keymap = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
							close (fd);

							if (keymap != MAP_FAILED) {
								d = dkim_sign (cfg->dkim_lib,
										(u_char *)"rmilter",
										NULL,
										(u_char *)keymap,
										(u_char *)dkim_domain->selector,
										(u_char *)domain,
										cfg->dkim_relaxed_header ?
												DKIM_CANON_RELAXED : DKIM_CANON_SIMPLE,
										cfg->dkim_relaxed_body ?
												DKIM_CANON_RELAXED : DKIM_CANON_SIMPLE,
										cfg->dkim_sign_sha256 ?
												DKIM_SIGN_RSASHA256 : DKIM_SIGN_RSASHA1,
										-1, &statp);

								/* It is safe to unmap memory here */
								munmap (keymap, st.st_size);

								if (statp != DKIM_STAT_OK) {
									msg_info ("<%s>; dkim sign failed: %s",
											priv->mlfi_id, dkim_geterror (d));

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
							else {
								msg_err ("<%s>; cannot mmmap key for domain %s at %s: %s",
										priv->mlfi_id, domain, fname,
										strerror (errno));
							}
						}
						else {
							msg_err ("<%s>; cannot open key for domain %s at %s: %s",
									priv->mlfi_id, domain, fname,
									strerror (errno));
						}
					}
					else {
						msg_info ("<%s>; cannot find key for domain %s at %s",
								priv->mlfi_id, domain, fname);
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
	char *tmpfrom;
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
		tmpfrom = "";
	}
	else if (strchr (tmpfrom, '@') == NULL) {
		/* Special case for sendmail */
		tmpfrom = envfrom[0];

		if (tmpfrom == NULL || *tmpfrom == '\0') {
			tmpfrom = "";
		}
	}

	normalize_email_addr (tmpfrom, priv->priv_from, sizeof (priv->priv_from));

	msg_debug ("<%s>; mlfi_envfrom: got from value: <%s>", priv->mlfi_id, priv->priv_from);

	if (priv->priv_hostname[0] == '\0') {
		tmpfrom = smfi_getsymval(ctx, "{client_name}");
		if (tmpfrom != NULL) {
			rmilter_strlcpy (priv->priv_hostname, tmpfrom, sizeof (priv->priv_hostname));
			msg_debug ("<%s>; mlfi_envfrom: got host value: %s", priv->mlfi_id, priv->priv_hostname);
		}
		else {
			rmilter_strlcpy (priv->priv_hostname, "unknown", sizeof (priv->priv_hostname));
		}
	}


	tmpfrom = smfi_getsymval(ctx, "{auth_authen}");
	if (tmpfrom != NULL) {
		priv->authenticated = 1;
		rmilter_strlcpy (priv->priv_user, tmpfrom, sizeof (priv->priv_user));
		msg_info ("<%s>; mlfi_envfrom: client is authenticated as: %s",
					priv->mlfi_id, priv->priv_user);
	}
	else if (radix_find_rmilter_addr (cfg->dkim_ip_tree, &priv->priv_addr) !=
			RADIX_NO_VALUE) {
		priv->authenticated = 1;
		rmilter_strlcpy (priv->priv_user, priv->priv_from, sizeof (priv->priv_user));
		msg_info ("<%s>; mlfi_envfrom: client comes from our network: %s",
				priv->mlfi_id, priv->priv_user);
	}

	/* Check whether we need to sign this message */
#ifdef WITH_DKIM
	CFG_RLOCK();
	DKIM_STAT statp;
	struct dkim_domain_entry *dkim_domain;
	char *domain_pos;

	domain_pos = strchr (priv->priv_from, '@');

	if (domain_pos) {
		HASH_FIND_STR (cfg->dkim_domains, domain_pos + 1, dkim_domain);

		if (!cfg->dkim_auth_only || priv->authenticated ||
				radix_find_rmilter_addr (cfg->dkim_ip_tree, &priv->priv_addr)
					!= RADIX_NO_VALUE) {
			if (dkim_domain && dkim_domain->is_loaded) {
				priv->dkim = dkim_sign (cfg->dkim_lib,  (u_char *)"rmilter", NULL,
						(u_char *)dkim_domain->key,  (u_char *)dkim_domain->selector,
						(u_char *)dkim_domain->domain,
						cfg->dkim_relaxed_header ? DKIM_CANON_RELAXED : DKIM_CANON_SIMPLE,
						cfg->dkim_relaxed_body ? DKIM_CANON_RELAXED : DKIM_CANON_SIMPLE,
						cfg->dkim_sign_sha256 ? DKIM_SIGN_RSASHA256 : DKIM_SIGN_RSASHA1, -1, &statp);

				if (statp != DKIM_STAT_OK) {
					msg_info ("<%s>; dkim sign failed: %s",
							priv->mlfi_id, dkim_geterror (priv->dkim));

					if (priv->dkim) {
						dkim_free (priv->dkim);
					}
					priv->dkim = NULL;
				}
				else {
					msg_debug ("<%s>; try to add signature for %s domain",
						priv->mlfi_id, dkim_domain->domain);
					priv->dkim_domain = dkim_domain;
				}
			}
			else {
				priv->dkim = try_wildcard_dkim (domain_pos + 1, priv);
				if (priv->dkim) {
					msg_debug ("<%s>; try to add signature for %s domain",
						priv->mlfi_id, domain_pos + 1);
				}
				else {
					if (dkim_domain) {
						msg_warn ("<%s>; cannot add signature for domain %s: "
								"not loaded key from %s",
								priv->mlfi_id,
								domain_pos + 1,
								dkim_domain->keyfile);
					}
					else {
						msg_info ("<%s>; cannot add signature for domain %s: "
								"not found",
								priv->mlfi_id,
								domain_pos + 1);
					}
				}
			}
		}
		else if (dkim_domain) {
			priv->dkim = NULL;
			msg_debug ("<%s>; do not add dkim signature for unauthorized user", priv->mlfi_id);
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

	DL_APPEND(priv->rcpts, newrcpt);
	priv->priv_rcptcount ++;
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
		rmilter_strlcpy (priv->queue_id, id, sizeof (priv->queue_id));
		msg_info ("<%s>; mlfi_data: queue id: <%s>", priv->mlfi_id,
				priv->queue_id);
	}
	else {
		rmilter_strlcpy (priv->queue_id, "NOQUEUE", sizeof (priv->queue_id));
		msg_err ("<%s>; mlfi_data: cannot get queue id, set to 'NOQUEUE'",
				priv->mlfi_id);
	}
	CFG_UNLOCK();

	if (priv->authenticated && !cfg->strict_auth) {
		msg_info ("<%s>; mlfi_envfrom: turn off strict checks for authenticated sender: %s",
				priv->mlfi_id, priv->priv_user);
		priv->strict = 0;
	}

	if (!cfg->spamd_greylist) {
		if (!priv->authenticated &&
				(r = check_greylisting_ctx (ctx, priv)) != SMFIS_CONTINUE) {
			msg_info ("<%s>; mlfi_eom: greylisting message", priv->mlfi_id);
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
	char *p, *c, t, *hname_lowercase;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		mlfi_cleanup (ctx, false);
		return SMFIS_TEMPFAIL;
	}

	hname_lowercase = strdup (headerf);

	if (hname_lowercase == NULL) {
		msg_err ("Internal error: strdup() returns NULL");
		mlfi_cleanup (ctx, false);
		return SMFIS_TEMPFAIL;
	}

	rmilter_str_lc (hname_lowercase, strlen (hname_lowercase));

	if (headerv && strcmp (hname_lowercase, "in-reply-to") == 0) {
		check_message_id (priv, headerv);
	}
	else if (headerv && strcmp (hname_lowercase, "references") == 0) {
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
	else if (strcmp (hname_lowercase, "return-path") == 0) {
		priv->has_return_path = 1;
	}

	/*
	 * Create temporary file, if this is first call of mlfi_header(), and it
	 * not yet created
	 */
	CFG_RLOCK();
	if (!priv->fileh) {
		if (create_temp_file (priv) == -1) {
			msg_err ("<%s>; mlfi_eoh: cannot create temp file", priv->mlfi_id);
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
		HASH_FIND_STR (cfg->headers, hname_lowercase, e);
		if (e) {
			tmplen = strlen (headerf) + strlen (headerv) + sizeof (": ");
			tmp = malloc (tmplen);

			if (tmp != NULL) {
				snprintf ((char *)tmp, tmplen, "%s: %s", headerf, headerv);
				r = dkim_header (priv->dkim, tmp, tmplen - 1);
				if (r != DKIM_STAT_OK) {
					msg_info ("<%s>; dkim_header failed: %s",
						priv->mlfi_id, dkim_geterror (priv->dkim));
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

	if (strcmp (hname_lowercase, "subject") == 0) {
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

	free (hname_lowercase);

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
			msg_err ("<%s>; mlfi_eoh: cannot create temp file", priv->mlfi_id);
			mlfi_cleanup (ctx, false);
			return SMFIS_TEMPFAIL;
		}
	}

	if (!priv->has_return_path && priv->fileh) {
		fprintf (priv->fileh, "Return-Path: <%s>\r\n", priv->priv_from);
	}
	if (priv->fileh) {
		DL_FOREACH (priv->rcpts, rcpt) {
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
			msg_info ("<%s>; mlfi_eoh: dkim_eoh failed: %s", priv->mlfi_id, dkim_geterror (priv->dkim));
		}
	}
#endif

	return SMFIS_CONTINUE;
}

static const char *
action_to_string (int act)
{
	const char *ret = "no action";

	switch (act) {
	case METRIC_ACTION_REJECT:
		ret = "reject";
		break;
	case METRIC_ACTION_ADD_HEADER:
		ret = "add header";
		break;
	case METRIC_ACTION_REWRITE_SUBJECT:
		ret = "rewrite subject";
		break;
	case METRIC_ACTION_SOFT_REJECT:
		ret = "soft reject";
		break;
	case METRIC_ACTION_GREYLIST:
		ret = "greylist";
		break;
	default:
		break;
	}

	return ret;
}

static sfsistat
mlfi_eom(SMFICTX * ctx)
{
	struct mlfi_priv *priv;
	int r, er;
#ifdef HAVE_PATH_MAX
	char strres[PATH_MAX], buf[PATH_MAX], extra_buf[128];
#elif defined(HAVE_MAXPATHLEN)
	char strres[MAXPATHLEN], buf[MAXPATHLEN ];
#else
#error "neither PATH_MAX nor MAXPATHEN defined"
#endif
	char tmpbuf[128], ip_str[INET6_ADDRSTRLEN + 1];
	char *id;
	int prob_max;
	double prob_cur;
	struct stat sb;
	struct action *act;
	struct rcpt *rcpt;
	bool ip_whitelisted = false;
	int ret = SMFIS_CONTINUE;
	struct rspamd_metric_result *mres = NULL;
	const char *spam_check_result = "unknown",
			*av_check_result = "unknown",
			*dkim_result = "unsigned";
	void *addr;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

	memset (extra_buf, 0, sizeof (extra_buf));

	/* set queue id */
	if (priv->queue_id[0] == '\0') {
		id = smfi_getsymval(ctx, "i");

		if (id) {
			rmilter_strlcpy (priv->queue_id, id, sizeof (priv->queue_id));
			msg_info ("<%s>; mlfi_data: queue id: %s", priv->mlfi_id,
					priv->queue_id);
		}
		else {
			rmilter_strlcpy (priv->queue_id, "NOQUEUE", sizeof (priv->queue_id));
			msg_err ("<%s>; mlfi_data: cannot get queue id, set to 'NOQUEUE'",
					priv->mlfi_id);
		}
	}


#if (SMFI_PROT_VERSION < 4)
	/* Do greylisting here if DATA callback is not available */
	if (!cfg->spamd_greylist) {
		if ((r = check_greylisting_ctx (ctx, priv)) != SMFIS_CONTINUE) {
			msg_info ("<%s>; mlfi_eom: greylisting message", priv->mlfi_id);
			mlfi_cleanup (ctx, false);
			return r;
		}
	}
#endif

	CFG_RLOCK();
	if (cfg->serial == priv->serial) {
		msg_debug ("<%s>; mlfi_eom: checking regexp rules", priv->mlfi_id);
		act = rules_check (priv->matched_rules);
		if (act != NULL && act->type != ACTION_ACCEPT) {
			CFG_UNLOCK ();
			return set_reply (ctx, act);
		}
	}
	else {
		msg_warn ("<%s>; mlfi_eom: config was reloaded, not checking rules", priv->mlfi_id);
	}

	if (priv->complete_to_beanstalk) {
		/* Set actual pos to send all message to beanstalk */
		priv->eoh_pos = ftell (priv->fileh);
	}

	fflush (priv->fileh);

	/* check file size */
	if (stat (priv->file, &sb) == -1) {
		msg_warn ("<%s>; mlfi_eom: stat failed: %s", priv->mlfi_id,
				strerror (errno));
		spam_check_result = "skipped(internal failure)";
		av_check_result = "skipped(internal failure)";
		dkim_result = "skipped(internal failure)";
		goto end;
	}
	else if (cfg->sizelimit != 0 && sb.st_size > (off_t)cfg->sizelimit) {
#ifndef FREEBSD_LEGACY
		msg_warn ("<%s>; mlfi_eom: message size(%zd) exceeds limit(%zd), not scanned, %s",
				priv->mlfi_id, (size_t)sb.st_size, cfg->sizelimit, priv->file);
#else
		msg_warn ("<%s>; mlfi_eom: message size(%ld) exceeds limit(%ld), not scanned, %s",
				priv->mlfi_id, (long int)sb.st_size, (long int)cfg->sizelimit, priv->file);
#endif
		spam_check_result = "skipped(oversized)";
		av_check_result = "skipped(oversized)";
		goto dkim_sign;
	}

	msg_info ("<%s>; mlfi_eom: tempfile=%s, size=%lu",
			priv->mlfi_id, priv->file, (unsigned long int)sb.st_size);

#ifdef HAVE_DCC
	/* Check dcc */
	if (cfg->use_dcc == 1 && !priv->has_whitelisted && priv->strict &&
			(cfg->strict_auth && *priv->priv_user != '\0')) {
		msg_debug ("<%s>; mlfi_eom: check dcc", priv->mlfi_id);
		r = check_dcc (priv);
		switch (r) {
		case 'A':
			break;
		case 'G':
			msg_warn ("<%s>; mlfi_eom: greylisting by dcc", priv->mlfi_id);
			smfi_setreply (ctx, RCODE_LATER, XCODE_TEMPFAIL, "Try again later");
			ret = SMFIS_TEMPFAIL;
			goto end;
		case 'R':
			msg_warn ("<%s>; mlfi_eom: rejected by dcc", priv->mlfi_id);
			smfi_setreply (ctx, "550", XCODE_REJECT, "Message content rejected");
			ret = SMFIS_REJECT;
			goto end;
		case 'S': /* XXX - dcc selective reject - not implemented yet */
		case 'T': /* Temp failure by dcc */
		default:
			break;
		}
	}
#endif
	if (radix_find_rmilter_addr (cfg->spamd_whitelist, &priv->priv_addr)
			!= RADIX_NO_VALUE) {
		ip_whitelisted = true;
	}

	/* Check spamd */
	if (cfg->spamd_servers_num != 0 && !priv->has_whitelisted && priv->strict
			&& !ip_whitelisted &&
			(cfg->strict_auth || *priv->priv_user == '\0')) {
		msg_debug ("<%s>; mlfi_eom: check spamd", priv->mlfi_id);
		mres = spamdscan (ctx, priv, cfg, 0);

		if (mres == NULL) {
			msg_warn ("<%s>; mlfi_eom: spamdscan() failed", priv->mlfi_id);

			if (cfg->spamd_temp_fail) {
				smfi_setreply (ctx, RCODE_LATER, XCODE_TEMPFAIL, "Temporary service failure.");
				ret = SMFIS_TEMPFAIL;
				spam_check_result = "delayed, temporary fail";
				av_check_result = "skipped, spamd tempfail";
				dkim_result = "skipped, spamd tempfail";
				goto end;
			}
			else {
				spam_check_result = "ignored, temporary fail";
				goto av_check;
			}
		}
		else {
			if (cfg->spamd_greylist && SPAM_IS_GREYLIST (mres) &&
					!priv->authenticated) {
				/* Perform greylisting */
				CFG_UNLOCK();
				/* Unlock config to avoid recursion, since check_greylisting locks cfg as well */
				if (check_greylisting_ctx (ctx, priv) != SMFIS_CONTINUE) {
					CFG_RLOCK();
					msg_info (
							"<%s>; mlfi_eom: greylisting message according to spamd action",
							priv->mlfi_id);
					snprintf (tmpbuf, sizeof (tmpbuf), "greylisted, action: %s",
							action_to_string (mres->action));
					spam_check_result = tmpbuf;

					ret = SMFIS_TEMPFAIL;
					av_check_result = "skipped, spamd greylist";
					dkim_result = "skipped, spamd greylist";
					goto end;
				}
				CFG_RLOCK();
			}

			switch (mres->action) {
			case METRIC_ACTION_REJECT:
				if (cfg->cache_servers_spam_num > 0 && cfg->cache_spam_channel) {
					publish_message (priv, RMILTER_PUBLISH_SPAM, extra_buf,
										sizeof (extra_buf));
				}

				if (!cfg->spamd_never_reject) {
					msg_info ("<%s>; mlfi_eom: rejecting spam", priv->mlfi_id);
					smfi_setreply (ctx, RCODE_REJECT, XCODE_REJECT,
							cfg->spamd_reject_message);
					snprintf (tmpbuf, sizeof (tmpbuf), "rejected, action: %s",
							action_to_string (mres->action));
					spam_check_result = tmpbuf;
					av_check_result = "skipped, spam detected";
					dkim_result = "skipped, spam detected";
					ret = SMFIS_REJECT;
					goto end;
				}
				else {
					/* Add header instead */

					if (!priv->authenticated) {
						if (cfg->spamd_greylist) {

						}
						msg_info (
								"<%s>, mlfi_eom: add spam header to message instead"
								" of rejection",
								priv->mlfi_id);
						smfi_chgheader (ctx,
								cfg->spam_header,
								1,
								cfg->spam_header_value);
						snprintf (tmpbuf, sizeof (tmpbuf), "add header, action: %s",
								action_to_string (mres->action));
						spam_check_result = tmpbuf;
					}
					else {
						if (!cfg->spam_no_auth_header) {
							msg_info (
									"<%s>; mlfi_eom: add spam header to message instead"
									" of rejection",
									priv->mlfi_id);
							smfi_chgheader (ctx,
									cfg->spam_header,
									1,
									cfg->spam_header_value);
							snprintf (tmpbuf, sizeof (tmpbuf), "add header, action: %s",
									action_to_string (mres->action));
							spam_check_result = tmpbuf;
						}
						else {
							spam_check_result = "ignored, authenticated user";
						}
					}
				}
				break; /* REJECT */
			case METRIC_ACTION_SOFT_REJECT:
				smfi_setreply (ctx, RCODE_LATER, XCODE_TEMPFAIL,
						mres->message ? mres->message : "Temporary failure");

				snprintf (tmpbuf, sizeof (tmpbuf), "delayed, action: %s",
						action_to_string (mres->action));
				spam_check_result = tmpbuf;
				av_check_result = "skipped, spam soft reject";
				dkim_result = "skipped, spam soft reject";
				ret = SMFIS_TEMPFAIL;
				goto end;
				break;
			case METRIC_ACTION_ADD_HEADER:
				if (!priv->authenticated || !cfg->spam_no_auth_header) {
					msg_info (
							"<%s>; mlfi_eom: add spam header to message according to spamd action",
							priv->mlfi_id);
					snprintf (tmpbuf, sizeof (tmpbuf), "action: %s",
							action_to_string (mres->action));
					spam_check_result = tmpbuf;
					smfi_chgheader (ctx,
							cfg->spam_header,
							1,
							cfg->spam_header_value);
				}
				else {
					spam_check_result = "ignored, authenticated user";
				}
				break;
			case METRIC_ACTION_REWRITE_SUBJECT:
				if (!priv->authenticated || !cfg->spam_no_auth_header) {
					if (!cfg->spamd_spam_add_header)	{
					    msg_info ("<%s>; mlfi_eom: rewriting spam subject",
						priv->mlfi_id);
					}
					else {
					    msg_info ("<%s>; mlfi_eom: rewriting spam subject and adding spam header",
						priv->mlfi_id);

					    smfi_chgheader (ctx, cfg->spam_header, 1, cfg->spam_header_value);
					}



					if (mres->subject == NULL) {
						/* Use own settings */
						if (priv->priv_subject) {
							smfi_chgheader (ctx, "Subject", 1, priv->priv_subject);
						}
						else {
							smfi_chgheader (ctx, "Subject", 1, SPAM_SUBJECT);
						}
					}
					else {
						smfi_chgheader (ctx, "Subject", 1, mres->subject);
					}

					snprintf (tmpbuf, sizeof (tmpbuf), "action: %s",
							action_to_string (mres->action));
					spam_check_result = tmpbuf;
				}
				else {
					spam_check_result = "ignored, authenticated user";
				}
				break;
			default:
				spam_check_result = "no spam";
				break;
			}
		} /* mres != NULL */
	}
	else {
		if (cfg->spamd_servers_num == 0) {
			spam_check_result = "skipped, no spamd servers defined";
		}
		else {
			spam_check_result = "skipped, whitelisted";
		}
	}

	/* Maybe write message copy */
	if (cfg->cache_servers_copy > 0 && cfg->cache_copy_channel) {
		prob_cur = cfg->cache_copy_prob;
		/* Normalize */
		prob_max = 100;
		while (prob_cur < 1.0) {
			prob_max *= 10;
			prob_cur *= 10;
		}

		if (prng_next (rng_state) % prob_max <= prob_cur) {
			publish_message (priv, RMILTER_PUBLISH_COPY, extra_buf,
					sizeof (extra_buf));
		}
	}

	ip_whitelisted = false;

	if (radix_find_rmilter_addr (cfg->clamav_whitelist, &priv->priv_addr)
			!= RADIX_NO_VALUE) {
		ip_whitelisted = true;
		av_check_result = "skipped, ip whitelist";
	}
	else if (priv->has_whitelisted) {
		av_check_result = "skipped, recipient whitelist";
	}


	if (cfg->clamav_servers_num == 0) {
		av_check_result = "skipped, no av servers";
	}

av_check:
	/* Check clamav */
	if (cfg->clamav_servers_num != 0 && !priv->has_whitelisted
			&& !ip_whitelisted) {
		msg_debug ("mlfi_eom: %s: check clamav", priv->mlfi_id);
		r = check_clamscan (ctx, priv, strres, sizeof (strres));
		if (r < 0) {
			if (cfg->spamd_temp_fail) {
				smfi_setreply (ctx, RCODE_LATER, XCODE_TEMPFAIL, "Temporary service failure.");
				ret = SMFIS_TEMPFAIL;
				av_check_result = "delayed, temporary fail";
				dkim_result = "skipped, clamav tempfail";
				goto end;
			}
			else {
				av_check_result = "ignored, temporary fail";
				goto dkim_sign;
			}
		}

		if (*strres) {
			msg_warn ("<%s>; mlfi_eom: rejecting virus %s", priv->mlfi_id, strres);
			snprintf (buf, sizeof (buf), "Infected: %s", strres);
			smfi_setreply (ctx, RCODE_REJECT, XCODE_REJECT, buf);
			ret = SMFIS_REJECT;
			av_check_result = "rejected, virus found";
			dkim_result = "skipped, clamav virus";
			goto end;
		}
		else {
			av_check_result = "clean";
		}
	}

	/* Update rate limits for message */
	msg_debug ("<%s>; mlfi_eom: updating rate limits", priv->mlfi_id);


dkim_sign:

#if 0
	char rcptbuf[8192];
	int rr = 0;
	DL_FOREACH (priv->rcpts, rcpt) {
		if (rr < sizeof (rcptbuf)) {
			rate_check (priv, cfg, rcpt->r_addr, 1);
			if (rcpt->r_list.le_next) {
				rr += snprintf (rcptbuf + rr, sizeof (rcptbuf) - rr, "%s, ", rcpt->r_addr);
			}
			else {
				rr += snprintf (rcptbuf + rr, sizeof (rcptbuf) - rr, "%s", rcpt->r_addr);
			}
		}
	}
	smfi_addheader (ctx, "X-Rcpt-To", rcptbuf);
#else
	DL_FOREACH (priv->rcpts, rcpt) {
		rate_check (priv, cfg, rcpt->r_addr, 1);
	}
#endif
	dkim_result = "not signed, ignored";
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
				msg_info ("<%s>; mlfi_eom: d=%s, s=%s, added DKIM signature",
						priv->mlfi_id,
						dkim_getdomain (priv->dkim),
						priv->dkim_domain->selector);
				smfi_addheader (ctx, DKIM_SIGNHEADER, dkim_stripcr (hdr));
				dkim_result = "signed";
			}
			else {
				msg_info ("<%s>; mlfi_eom: d=%s, s=%s, sign failed: %s",
						priv->mlfi_id,
						dkim_getdomain (priv->dkim),
						priv->dkim_domain->selector,
						dkim_geterror (priv->dkim));
				dkim_result = "not signed, internal failure";
			}
		}
		else {
			msg_info ("<%s>; mlfi_eom: d=%s, s=%s, dkim_eom failed: %s",
					priv->mlfi_id,
					dkim_getdomain (priv->dkim),
					priv->dkim_domain->selector,
					dkim_geterror (priv->dkim));
			dkim_result = "not signed, internal failure";
		}
	}
#endif

end:

	addr = priv->priv_addr.family == AF_INET6
		  ? (void *) &priv->priv_addr.addr.sa6.sin6_addr :
		  (void *) &priv->priv_addr.addr.sa4.sin_addr;
	memset (ip_str, 0, sizeof (ip_str));
	inet_ntop (priv->priv_addr.family, addr, ip_str, sizeof (ip_str) - 1);
	msg_info ("<%s>; msg done: queue_id: <%s>; "
			"message id: <%s>; ip: %s; "
			"from: <%s>; rcpt: %s (%d total); user: %s; "
			"spam scan: %s; virus scan: %s; dkim: %s%s",
			priv->mlfi_id,
			priv->queue_id,
			priv->message_id,
			ip_str,
			priv->priv_from,
			priv->rcpts->r_addr,
			priv->priv_rcptcount,
			priv->priv_user[0] ? priv->priv_user : "unauthorized",
			spam_check_result,
			av_check_result,
			dkim_result,
			extra_buf);

	if (mres != NULL) {
		spamd_free_result (mres);
	}

	CFG_UNLOCK();
	mlfi_cleanup (ctx, true);
	return ret;
}

static sfsistat
mlfi_close(SMFICTX * ctx)
{
	struct mlfi_priv *priv;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}
	msg_debug ("<%s>; mlfi_close: cleanup", priv->mlfi_id);

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
	struct rcpt *rcpt, *tmp;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}
	msg_debug ("<%s>; mlfi_cleanup: cleanup", priv->mlfi_id);

	if (priv->fileh) {
		if (fclose (priv->fileh) != 0) {
			msg_err ("<%s>; mlfi_close: close failed: %s", priv->mlfi_id,
					strerror (errno));
		}
		priv->fileh = NULL;
	}
	if (*priv->file) {
		unlink (priv->file);
		priv->file[0] = '\0';
	}
	/* clean message specific data */
	priv->strict = 1;
	/* Create new ID */
	set_random_id (priv);
	priv->reply_id[0] = '\0';
	priv->queue_id[0] = '\0';
	priv->message_id[0] = '\0';
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

		DL_FOREACH_SAFE (priv->rcpts, rcpt, tmp) {
			free (rcpt);
		}

		priv->rcpts = NULL;
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
			msg_err ("<%s>; mlfi_body: cannot create temp file", priv->mlfi_id);
			mlfi_cleanup (ctx, false);
			return SMFIS_TEMPFAIL;
		}
	}


	if (fwrite (bodyp, bodylen, 1, priv->fileh) != 1) {
		msg_warn ("<%s>; mlfi_body: file write error: %s", priv->mlfi_id,
				strerror (errno));
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
			msg_info ("<%s>; mlfi_body: dkim_body failed: %s", priv->mlfi_id,
					dkim_geterror (priv->dkim));
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
check_clamscan(void *ctx, struct mlfi_priv *priv,
		char *strres, size_t strres_len)
{
	int r = -2;

	*strres = '\0';

	/* scan using libclamc clamscan() */
	r = clamscan (ctx, priv, cfg, strres, strres_len);

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
		msg_warn ("<%s>; check_dcc: dcc data file open(): %s", priv->mlfi_id, strerror (errno));
		return 0;
	}

	dcc_mk_su (&sup, priv->priv_addr.family, &priv->priv_addr.addr.sa, 0);

	rcpt.next = rcpts;
	rcpt.addr = priv->rcpts->r_addr;
	rcpt.user = "";
	rcpt.ok = '?';
	rcpts = &rcpt;

	dccres = dccif (emsg, /*out body fd*/dccofd, /*out_body*/0,
			opts, &sup, priv->priv_hostname, priv->priv_helo,
			(priv->priv_from[0] == 0) ? "<>" : priv->priv_from,
			rcpts, dccfd, /*in_body*/0, homedir);

	return dccres;
}
#endif

/*
 * vi:ts=4
 */
