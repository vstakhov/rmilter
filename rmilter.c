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

#include <libmilter/mfapi.h>
#include "spf2/spf.h"

#include "libclamc.h"
#include "cfg_file.h"
#include "spf.h"
#include "rmilter.h"
#include "regexp.h"
#include "dccif.h"

/* config options here... */

struct config_file *cfg;

#ifndef true
typedef int bool;
#define false	0
#define true	1
#endif				/* ! true */

/* Global mutexes */

pthread_mutex_t mkstemp_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t regexp_mtx = PTHREAD_MUTEX_INITIALIZER;


static sfsistat mlfi_cleanup(SMFICTX *, bool);
static int check_clamscan(const char *, char *, size_t);
static int check_dcc(const struct mlfi_priv *);

int
my_strcmp (const void *s1, const void *s2)
{
	return strcmp (*(const char **)s1, *(const char **)s2);
}

static void 
usage (void)
{
	printf ("Usage: rmilter [-h] -c <config_file>\n"
			"-h - this help message\n"
			"-c - path to config file\n");
	exit (0);
}

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

	/* Check connect */
	pthread_mutex_lock (&regexp_mtx);
	act = regexp_check (cfg, priv, STAGE_CONNECT);
	pthread_mutex_unlock (&regexp_mtx);
	if (act != NULL) {
		return set_reply (ctx, act);
	}
	/* Check helo */
	pthread_mutex_lock (&regexp_mtx);
	act = regexp_check (cfg, priv, STAGE_HELO);
	pthread_mutex_unlock (&regexp_mtx);
	if (act != NULL) {
		return set_reply (ctx, act);
	}

	return SMFIS_CONTINUE;
}



static sfsistat
mlfi_envfrom(SMFICTX *ctx, char **envfrom)
{
	char tmpfrom[ADDRLEN + 1];
	char *idx;
	struct mlfi_priv *priv;
	struct action *act;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

	/*
	 * Strip spaces from the source address
	 */
	strlcpy (tmpfrom, *envfrom, ADDRLEN);

	/* 
	 * Strip anything before the last '=' in the
	 * source address. This avoid problems with
	 * mailing lists using a unique sender address
	 * for each retry.
	 */
	if ((idx = rindex (tmpfrom, '=')) == NULL)
		idx = tmpfrom;

	strlcpy (priv->priv_from, idx, ADDRLEN);

	/* Check envfrom */
	pthread_mutex_lock (&regexp_mtx);
	act = regexp_check (cfg, priv, STAGE_ENVFROM);
	pthread_mutex_unlock (&regexp_mtx);
	if (act != NULL) {
		return set_reply (ctx, act);
	}

	return SMFIS_CONTINUE;
}

static sfsistat
mlfi_envrcpt(SMFICTX *ctx, char **envrcpt)
{
	struct mlfi_priv *priv;
	struct action *act;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		msg_err ("Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}
	/* Copy first recipient to priv - this is needed for dcc checking */
	if (!priv->priv_cur_rcpt) {
		strlcpy (priv->priv_rcpt, *envrcpt, sizeof (priv->priv_rcpt));
	}
	/* Check recipient */
	priv->priv_cur_rcpt = *envrcpt;
	pthread_mutex_lock (&regexp_mtx);
	act = regexp_check (cfg, priv, STAGE_ENVRCPT);
	pthread_mutex_unlock (&regexp_mtx);
	if (act != NULL) {
		return set_reply (ctx, act);
	}

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
	pthread_mutex_lock (&regexp_mtx);
	priv->priv_cur_header.header_name = headerf;
	priv->priv_cur_header.header_value = headerv;
	act = regexp_check (cfg, priv, STAGE_HEADER);
	pthread_mutex_unlock (&regexp_mtx);
	if (act != NULL) {
		return set_reply (ctx, act);
	}

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
				msg_warn ("(mlfi_eom, %s) rejecting sender %s due to SPF policy violations", priv->mlfi_id, priv->priv_from);
	    		smfi_setreply(ctx, RCODE_REJECT, XCODE_REJECT, "SPF policy violation");
				(void)mlfi_cleanup (ctx, false);
				return SMFIS_REJECT;
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
	/* Check dcc */
	if (cfg->use_dcc == 1) {
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
	pthread_mutex_lock (&regexp_mtx);
	priv->priv_cur_body.value = (char *)bodyp;
	priv->priv_cur_body.len = bodylen;
	act = regexp_check (cfg, priv, STAGE_BODY);
	pthread_mutex_unlock (&regexp_mtx);
	if (act != NULL) {
		return set_reply (ctx, act);
	}
    /* continue processing */
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
	int dccfd;

	if (!*priv->file) {
		return 0;
	}

	if (priv->fileh) {
		fclose (priv->fileh);
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
	
	dccres = dccif (emsg, /*out body fd*/-1, /*out_body*/0,
					opts, &sup, priv->priv_hostname, priv->priv_helo,
					(priv->priv_from == 0) || (priv->priv_from[0] == 0) ? "<>" : priv->priv_from,
					rcpts, dccfd, /*in_body*/0, homedir);
	close (dccfd);

	return dccres;
}



/*****************************************************************************/



int main(int argc, char *argv[])
{
    int c, r;
	extern int yynerrs;
	extern FILE *yyin;
    const char *args = "c:h";
	char *cfg_file = NULL;
	FILE *f;

	struct smfiDesc smfilter =
	{
    	"rmilter",			/* filter name */
    	SMFI_VERSION,		/* version code -- do not change */
    	SMFIF_ADDHDRS,		/* flags */
    	mlfi_connect,		/* connection info filter */
    	mlfi_helo,				/* SMTP HELO command filter */
    	mlfi_envfrom,				/* envelope sender filter */
    	mlfi_envrcpt,				/* envelope recipient filter */
    	mlfi_header,		/* header filter */
    	mlfi_eoh,			/* end of header */
    	mlfi_body,			/* body block filter */
    	mlfi_eom,			/* end of message */
    	mlfi_abort,			/* message aborted */
    	mlfi_close,			/* connection cleanup */
		NULL,				/* unknown situation */
		NULL,				/* SMTP DATA callback */
		NULL				/* Negotiation callback */
	};

    /* Process command line options */
    while ((c = getopt(argc, argv, args)) != -1) {
		switch (c) {
		case 'c':
	    	if (optarg == NULL || *optarg == '\0') {
				fprintf(stderr, "Illegal config_file: %s\n",
			      optarg);
				exit(EX_USAGE);
	 	   	}
			else {
				cfg_file = strdup (optarg);
			}
	    	break;
		case 'h':
		default:
			usage ();
	    	break;
		}
    }


    openlog("rmilter", LOG_PID, LOG_MAIL);
    msg_warn ("(main) starting...");
	
	cfg = (struct config_file*) malloc (sizeof (struct config_file));
	if (cfg == NULL) {
		msg_warn ("malloc: %s", strerror (errno));
		return -1;
	}
	bzero (cfg, sizeof (struct config_file));

	LIST_INIT (&cfg->rules);
	cfg->spf_domains = (char **) calloc (MAX_SPF_DOMAINS, sizeof (char *));
	
	if (cfg_file == NULL) {
		cfg_file = strdup ("/usr/local/etc/rmilter.conf");
	}

	f = fopen (cfg_file, "r");
	if (f == NULL) {
		msg_warn ("cannot open file: %s", cfg_file);
		return EBADF;
	}
	yyin = f;

	if (yyparse() != 0 || yynerrs > 0) {
		msg_warn ("yyparse: cannot parse config file, %d errors", yynerrs);
		return EBADF;
	}

	/* Strictly set temp dir */
    if (!cfg->temp_dir) {
		msg_warn ("tempdir is not set, trying to use $TMPDIR");
		cfg->temp_dir = getenv("TMPDIR");

		if (!cfg->temp_dir) {
	    	cfg->temp_dir = strdup("/tmp");
		}
    }
	if (cfg->sizelimit == 0) {
		msg_warn ("maxsize is not set, no limits on size of scanned mail");
	}

	/* Sort spf domains array */
	qsort ((void *)cfg->spf_domains, cfg->spf_domains_num, sizeof (char *), my_strcmp);

	cfg->clamav_servers_alive = cfg->clamav_servers_num;
    srandomdev();

    /*
     * Hack to set milter unix socket permissions, but it also affect
     * temporary file too :( temporary directory shuld be owned by user
     * rmilter-clam and have permissions 700
     */
    umask(0007);

	smfi_setconn(cfg->sock_cred);
	if (smfi_register(smfilter) == MI_FAILURE) {
		msg_err ("smfi_register failed");
		exit(EX_UNAVAILABLE);
	}

    r = smfi_main();

	if (cfg_file != NULL) free (cfg_file);

    return r;
}

/* eof */
