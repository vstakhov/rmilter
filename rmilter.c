/******************************************************************************

	Rambler Milter

	Differs from clamav-milter in two major ways:

		- store message to disk, then scan (saves expansive
		connections to clamd)
		- do not shutdown clamd control socket until scanning is
		done (required by internal rambler.ru scalability patches
		to clamd)

	Rmilter-clam was originally written by Maxim Dounin, mdounin@rambler-co.ru

	$Id$

******************************************************************************/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <syslog.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <db.h>
#include <errno.h>
#include <fcntl.h>
#include <md5.h>

/* XXX hack to work on FreeBSD < 7 */
#define SMFI_VERSION 4
#include <libmilter/mfapi.h>
#include "spf2/spf.h"

#include "libclamc.h"
#include "cfg_file.h"
#include "spf.h"
#include "rmilter.h"
#include "regexp.h"
#include "dccif.h"
#include "ratelimit.h"

#ifndef true
typedef int bool;
#define false	0
#define true	1
#endif				/* ! true */

#define MD5_SIZE 16

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
static int check_dcc(const struct mlfi_priv *);

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
		NULL,			/* unknown situation */
		mlfi_data,		/* SMTP DATA callback */
		NULL			/* Negotiation callback */
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

	priv->priv_cur_rcpt = NULL;
	priv->priv_rcptcount = 0;

	if (addr != NULL) {
		switch (addr->sa_family) {
		case AF_INET:
			memcpy(&priv->priv_addr, addr, sizeof (struct sockaddr_in));
			inet_ntop (AF_INET, &priv->priv_addr.sin_addr, priv->priv_ip, INET_ADDRSTRLEN);
			if (hostname != NULL)
				strlcpy (priv->priv_hostname, hostname, sizeof (priv->priv_hostname));
			break;
		default:
			msg_warn ("bad client address");
		}
	}
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
	struct action *act;

	priv = (struct mlfi_priv *) smfi_getpriv (ctx);

	strlcpy (priv->priv_helo, helostr, ADDRLEN);
	
	CFG_RLOCK();
	/* Check connect */
	act = regexp_check (cfg, priv, STAGE_CONNECT);
	if (act != NULL) {
		return set_reply (ctx, act);
	}
	/* Check helo */
	act = regexp_check (cfg, priv, STAGE_HELO);
	if (act != NULL) {
		return set_reply (ctx, act);
	}

	CFG_UNLOCK();

	return SMFIS_CONTINUE;
}



static sfsistat
mlfi_envfrom(SMFICTX *ctx, char **envfrom)
{
	char *tmpfrom;
	struct mlfi_priv *priv;
	struct action *act;

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
    strlcpy (priv->priv_from, tmpfrom, sizeof(priv->priv_from));

	CFG_RLOCK();
	/* Check envfrom */
	act = regexp_check (cfg, priv, STAGE_ENVFROM);
	if (act != NULL) {
		return set_reply (ctx, act);
	}

	CFG_UNLOCK();
	return SMFIS_CONTINUE;
}

static sfsistat
mlfi_envrcpt(SMFICTX *ctx, char **envrcpt)
{
	struct mlfi_priv *priv;
	struct action *act;
	char *tmprcpt;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}
	/*
	 * Get recipient address
	 */
    tmprcpt = smfi_getsymval(ctx, "{rcpt_addr}");
    if (tmprcpt == NULL || *tmprcpt == '\0') {
		tmprcpt = "<>";
	}
	/* Copy first recipient to priv - this is needed for dcc checking and ratelimits */
	if (!priv->priv_cur_rcpt) {
		strlcpy (priv->priv_rcpt, tmprcpt, sizeof (priv->priv_rcpt));
	}
	CFG_RLOCK();
	/* Check ratelimit */
	priv->priv_cur_rcpt = tmprcpt;
	if (rate_check (priv, cfg, 0) == 0) {
		/* Rate is more than limit */
		if (smfi_setreply (ctx, RCODE_TEMPFAIL, XCODE_TEMPFAIL, (char *)"Rate limit exceeded") != MI_SUCCESS) {
			msg_err("smfi_setreply");
		}
	    (void)mlfi_cleanup (ctx, false);
		return SMFIS_TEMPFAIL;
	}
	/* Check recipient */
	act = regexp_check (cfg, priv, STAGE_ENVRCPT);
	if (act != NULL) {
		return set_reply (ctx, act);
	}

	CFG_UNLOCK();
	return SMFIS_CONTINUE;
}

static sfsistat
mlfi_data(SMFICTX *ctx)
{
    struct mlfi_priv *priv;
	MD5_CTX mdctx;
	u_char final[MD5_SIZE];
	char md5_out[MD5_SIZE * 2 + 1];
	struct memcached_server *selected;
	memcached_ctx_t mctx;
	memcached_param_t cur_param;
	struct timeval tm, tm1;
	int r;
	size_t s;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

	CFG_RLOCK();
	if (priv->priv_ip[0] != '\0' && priv->priv_cur_rcpt != NULL && cfg->memcached_servers_num > 0 &&
		cfg->greylisting_timeout > 0 && cfg->greylisting_expire > 0) {
		/* Check whitelist */
		if (radix32tree_find (cfg->grey_whitelist_tree, (uint32_t)priv->priv_addr.sin_addr.s_addr) == RADIX_NO_VALUE) {
			if (cfg->awl_enable && awl_check ((uint32_t)priv->priv_addr.sin_addr.s_addr, cfg->awl_hash, priv->conn_tm.tv_sec) == 1) {
				/* Auto whitelisted */
				CFG_UNLOCK();
				return SMFIS_CONTINUE;
			}
			bzero (&cur_param, sizeof (cur_param));
			MD5Init(&mdctx);
			/* Make hash from components: envfrom, ip address, envrcpt */
			MD5Update(&mdctx, (const u_char *)priv->priv_from, strlen(priv->priv_from));
			MD5Update(&mdctx, (const u_char *)priv->priv_ip, strlen(priv->priv_ip));
			MD5Update(&mdctx, (const u_char *)priv->priv_cur_rcpt, strlen(priv->priv_cur_rcpt));
			MD5Final(final, &mdctx);
			
			tm.tv_sec = priv->conn_tm.tv_sec;
			tm.tv_usec = priv->conn_tm.tv_usec;

			selected = (struct memcached_server *) get_upstream_by_hash ((void *)cfg->memcached_servers,
											cfg->memcached_servers_num, sizeof (struct memcached_server),
											(time_t)tm.tv_sec, cfg->memcached_error_time, cfg->memcached_dead_time, cfg->memcached_maxerrors,
											(char *)final, MD5_SIZE);
			if (selected == NULL) {
				msg_err ("mlfi_data: cannot get memcached upstream");
				CFG_UNLOCK();
	    		(void)mlfi_cleanup (ctx, false);
				return SMFIS_TEMPFAIL;
			}
			mctx.protocol = cfg->memcached_protocol;
			memcpy(&mctx.addr, &selected->addr, sizeof (struct in_addr));
			mctx.port = selected->port;
			mctx.timeout = cfg->memcached_connect_timeout;

			if (memc_init_ctx (&mctx) == -1) {
				msg_err ("mlfi_data: cannot connect to memcached upstream");
				upstream_fail (&selected->up, tm.tv_sec);
				CFG_UNLOCK();
	    		(void)mlfi_cleanup (ctx, false);
				return SMFIS_TEMPFAIL;
			}
			/* Format md5 output */
			s = sizeof (md5_out);
			for (r = 0; r < MD5_SIZE; r ++){
				s -= snprintf (md5_out + r * 2, s, "%02x", final[r]);
			}
			memcpy (cur_param.key, md5_out, sizeof (md5_out));

			s = 1;
			cur_param.buf = (u_char *)&tm1;
			cur_param.bufsize = sizeof (tm1);
			/* Try to get record from memcached */
			r = memc_get (&mctx, &cur_param, &s);
			if (r == NOT_EXISTS) {
				s = 1;
				/* Write record to memcached */
				cur_param.buf = (u_char *)&tm;
                cur_param.bufsize = sizeof (tm);
				if ((r = memc_set (&mctx, &cur_param, &s, cfg->greylisting_expire)) == OK) {
					upstream_ok (&selected->up, tm.tv_sec);
					if (smfi_setreply (ctx, RCODE_TEMPFAIL, XCODE_TEMPFAIL, (char *)"Try again later") != MI_SUCCESS) {
						msg_err("mlfi_data: smfi_setreply failed");
					}
					CFG_UNLOCK();
	    			(void)mlfi_cleanup (ctx, false);
					return SMFIS_TEMPFAIL;
				}
				else {
					msg_info ("mlfi_data: cannot write to memcached: %s", memc_strerror (r));
				}
			}
			else if (r == OK) {
				if (tm.tv_sec - tm1.tv_sec < cfg->greylisting_timeout) {
					/* Client comes too early */
					upstream_ok (&selected->up, tm.tv_sec);
					if (smfi_setreply (ctx, RCODE_TEMPFAIL, XCODE_TEMPFAIL, (char *)"Try again later") != MI_SUCCESS) {
						msg_err("mlfi_data: smfi_setreply failed");
					}
					CFG_UNLOCK();
	    			(void)mlfi_cleanup (ctx, false);
					return SMFIS_TEMPFAIL;
				}
			}
			else {
					upstream_fail (&selected->up, tm.tv_sec);
			}
			memc_close_ctx (&mctx);
		}
	}
	CFG_UNLOCK();
	return SMFIS_CONTINUE;
}

static sfsistat 
mlfi_header(SMFICTX * ctx, char *headerf, char *headerv)
{
    struct mlfi_priv *priv;
    char buf[PATH_MAX];
    int fd;
	struct action *act;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
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
	    	msg_warn ("(mlfi_header) mkstemp failed, %d: %m", errno);
	    	(void)mlfi_cleanup (ctx, false);
	    	return SMFIS_TEMPFAIL;
		}
		priv->fileh = fdopen(fd, "w");

		if (!priv->fileh) {
	    	msg_warn ("(mlfi_header) can't open tempfile, %d: %m", errno);
	    	(void)mlfi_cleanup(ctx, false);
	    	return SMFIS_TEMPFAIL;
		}
		fprintf (priv->fileh, "Received: from %s\n", priv->priv_ip); 
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
		return set_reply (ctx, act);
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
		return SMFIS_TEMPFAIL;
	}

    fprintf (priv->fileh, "\n");
    return SMFIS_CONTINUE;
}

static sfsistat 
mlfi_eom(SMFICTX * ctx)
{
    struct mlfi_priv *priv;
    int r;
    char strres[PATH_MAX], buf[PATH_MAX];
    char *id;
    struct stat sb;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

    /* set queue id */
    id = smfi_getsymval(ctx, "i");
    if (id == NULL) {
		id = "NOQUEUE";
	}
    strlcpy (priv->mlfi_id, id, sizeof(priv->mlfi_id));

	CFG_RLOCK();
	/* Update rate limits for message */
	priv->priv_cur_rcpt = priv->priv_rcpt;
	if (rate_check (priv, cfg, 1) == 0) {
		/* Rate is more than limit */
		if (smfi_setreply (ctx, RCODE_REJECT, XCODE_REJECT, (char *)"Rate limit exceeded") != MI_SUCCESS) {
			msg_err("smfi_setreply");
		}
		(void)mlfi_cleanup (ctx, false);
		return SMFIS_REJECT;
	}
	/*
	 * Is the sender address SPF-compliant?
	 */
	if (cfg->spf_domains_num > 0) {
		r = spf_check (priv, cfg);
		switch (r) {
			case SPF_RESULT_PASS:
			case SPF_RESULT_SOFTFAIL:
			case SPF_RESULT_NEUTRAL:
			case SPF_RESULT_NONE:
				break;
			case SPF_RESULT_FAIL:
				msg_warn ("(mlfi_eom, %s) SPF check failed. Host %s[%s] is not allowed to send mail as %s ", 
							priv->mlfi_id, (*priv->priv_hostname != '\0') ? priv->priv_hostname : "unresolved", 
							priv->priv_ip, priv->priv_from);

				if (priv->priv_cur_rcpt != NULL && !is_whitelisted_rcpt (priv->priv_cur_rcpt)) {
	    			smfi_setreply(ctx, RCODE_REJECT, XCODE_REJECT, "SPF policy violation");
					(void)mlfi_cleanup (ctx, false);
					return SMFIS_REJECT;
				}
				break;
		}
	}

    msg_warn ("%s: tempfile=%s", priv->mlfi_id, priv->file);

    fflush (priv->fileh);

    /* check file size */
    stat(priv->file, &sb);
    if (cfg->sizelimit != 0 && sb.st_size > cfg->sizelimit) {
		msg_warn ("message size exceeds limit, not scanned, %s", priv->file);
		return mlfi_cleanup (ctx, true);
	}

 	/* Check dcc */
	if (cfg->use_dcc == 1 && !is_whitelisted_rcpt (priv->priv_cur_rcpt)) {
		r = check_dcc (priv);
		switch (r) {
			case 'A':
				break;
			case 'G':
				msg_warn ("(mlfi_eom, %s) greylisting by dcc", priv->mlfi_id);
				smfi_setreply (ctx, RCODE_TEMPFAIL, XCODE_TEMPFAIL, "Try again later");
				mlfi_cleanup (ctx, false);
				return SMFIS_TEMPFAIL;
			case 'R':
				msg_warn ("(mlfi_eom, %s) rejected by dcc", priv->mlfi_id);
				smfi_setreply (ctx, "550", XCODE_REJECT, "Message content rejected");
				mlfi_cleanup (ctx, false);
				return SMFIS_REJECT;
			case 'S': /* XXX - dcc selective reject - not implemented yet */
			case 'T': /* Temp failure by dcc */
			default:
				break;
		}
	}
	
	/* Check clamav */
	if (cfg->clamav_servers_num != 0) {
	    r = check_clamscan (priv->file, strres, PATH_MAX);
    	if (r < 0) {
			msg_warn ("(mlfi_eom, %s) check_clamscan() failed, %d", priv->mlfi_id, r);
			(void)mlfi_cleanup (ctx, false);
			return SMFIS_TEMPFAIL;
    	}
    	if (*strres) {
			msg_warn ("(mlfi_eom, %s) rejecting virus %s", priv->mlfi_id, strres);
			snprintf (buf, sizeof (buf), "Infected: %s", strres);
			smfi_setreply (ctx, RCODE_REJECT, XCODE_REJECT, buf);
			mlfi_cleanup (ctx, false);
			return SMFIS_REJECT;
    	}
	}

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

    /* release message-related memory */
    priv->mlfi_id[0] = '\0';
    if (priv->fileh) {
		fclose (priv->fileh);
		priv->fileh = NULL;
    }
    if (*priv->file) {
		unlink (priv->file);
		*priv->file = '\0';
    }
    /* return status */
    return rstat;
}

static sfsistat 
mlfi_body(SMFICTX * ctx, u_char * bodyp, size_t bodylen)
{
    struct mlfi_priv *priv;
	struct action *act;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

    if (fwrite (bodyp, bodylen, 1, priv->fileh) != 1) {
		msg_warn ("(mlfi_body, %s) file write error, %d: %m", priv->mlfi_id, errno);
		(void)mlfi_cleanup (ctx, false);
		return SMFIS_TEMPFAIL;;
    }
	/* Check body with regexp */
	priv->priv_cur_body.value = (char *)bodyp;
	priv->priv_cur_body.len = bodylen;
	CFG_RLOCK();

	act = regexp_check (cfg, priv, STAGE_BODY);
	if (act != NULL) {
		return set_reply (ctx, act);
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
		msg_warn ("dcc data file open(): %s", strerror (errno));
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

/* 
 * vi:ts=4 
 */
