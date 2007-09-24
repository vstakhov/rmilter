/******************************************************************************

	Rambler Milter

	Differs from clamav-milter in two major ways:

		- store message to disk, then scan (saves expansive
		connections to clamd)
		- do not shutdown clamd control socket until scanning is
		done (required by internal rambler.ru scalability patches
		to clamd)

	Usage:
	rmilter -c config_file

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

#include "libmilter/mfapi.h"
#include "libclamc.h"
#include "cfg_file.h"
#include "spf.h"
#include "rmilter.h"

/* config options here... */

char *var_clamd_socket = NULL;
char *var_tempdir = NULL;
size_t var_sizelimit = 1024 * 1024;

struct config_file *cfg;

#ifndef true
typedef int bool;
#define false	0
#define true	1
#endif				/* ! true */

/* Global mutexes */

pthread_mutex_t mkstemp_mtx = PTHREAD_MUTEX_INITIALIZER;


static sfsistat mlfi_cleanup(SMFICTX *, bool);
static int check_clamscan(const char *file, char *strres, size_t strres_len);

static void 
usage (void)
{
	printf ("Usage: rmilter [-h] -c <config_file>\n"
			"-h - this help message\n"
			"-c - path to config file\n");
	exit (0);
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

	LIST_INIT(&priv->priv_rcpt);
	priv->priv_cur_rcpt = NULL;
	priv->priv_rcptcount = 0;
	TAILQ_INIT(&priv->priv_header);
	TAILQ_INIT(&priv->priv_body);

	if (addr != NULL) {
		switch (addr->sa_family) {
		case AF_INET:
			memcpy(&priv->priv_addr, addr, sizeof (struct sockaddr_in));
			break;
		default:
			syslog (LOG_WARNING, "bad client address");
		}
	}

    smfi_setpriv(ctx, priv);

    return SMFIS_CONTINUE;
}

static sfsistat
mlfi_helo(SMFICTX *ctx, char *helostr)
{
	struct mlfi_priv *priv;

	priv = (struct mlfi_priv *) smfi_getpriv (ctx);

	strlcpy (priv->priv_helo, helostr, ADDRLEN);
	priv->priv_helo[ADDRLEN] = '\0';

	return SMFIS_CONTINUE;
}



static sfsistat
mlfi_envfrom(SMFICTX *ctx, char **envfrom)
{
	char tmpfrom[ADDRLEN + 1];
	char *idx;
	struct mlfi_priv *priv;
	struct rcpt *r;
	struct header *h;
	struct body *b;

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		syslog (LOG_ERR, "Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

	while ((r = LIST_FIRST (&priv->priv_rcpt)) != NULL) {
		LIST_REMOVE (r, r_list);
		free (r);
	}
	while ((h = TAILQ_FIRST (&priv->priv_header)) != NULL) {
		free (h->h_line);
		TAILQ_REMOVE (&priv->priv_header, h,  h_list);
		free(h);
	}
	while ((b = TAILQ_FIRST (&priv->priv_body)) != NULL) {
		free (b->b_lines);
		TAILQ_REMOVE (&priv->priv_body, b, b_list);
		free (b);
	}

	/*
	 * Strip spaces from the source address
	 */
	strlcpy (tmpfrom, *envfrom, ADDRLEN);
	tmpfrom[ADDRLEN] = '\0';

	/* 
	 * Strip anything before the last '=' in the
	 * source address. This avoid problems with
	 * mailing lists using a unique sender address
	 * for each retry.
	 */
	if ((idx = rindex (tmpfrom, '=')) == NULL)
		idx = tmpfrom;

	strlcpy (priv->priv_from, idx, ADDRLEN);
	priv->priv_from[ADDRLEN] = '\0';

	/*
	 * Is the sender address SPF-compliant?
	 */
	if (spf_check (priv)) {
		return SMFIS_CONTINUE;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
mlfi_envrcpt(SMFICTX *ctx, char **envrcpt)
{
	struct mlfi_priv *priv;
	char rcpt[ADDRLEN + 1];

	/*
	 * Strip spaces from the recipient address
	 */
	strlcpy (rcpt, *envrcpt, ADDRLEN);
	rcpt[ADDRLEN] = '\0';

	if ((priv = (struct mlfi_priv *) smfi_getpriv (ctx)) == NULL) {
		syslog (LOG_ERR, "Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

	/* TODO: Add acl check and rbl/dcc checks */

	return SMFIS_CONTINUE;
}

static sfsistat 
mlfi_header(SMFICTX * ctx, char *headerf, char *headerv)
{
    struct mlfi_priv *priv = MLFIPRIV;
    char buf[MAXPATHLEN];
    int fd;

    /*
     * Create temporary file, if this is first call of mlfi_header(), and it
     * not yet created
     */

    if (!priv->fileh) {
		snprintf (buf, MAXPATHLEN, "%s/msg.XXXXXXXX", var_tempdir);
		priv->file = strdup(buf);
		/* mkstemp is based on arc4random (3) and is not reentrable
		 * so acquire mutex for it
		 */
		pthread_mutex_lock (&mkstemp_mtx);
		fd = mkstemp (priv->file);
		pthread_mutex_unlock (&mkstemp_mtx);

		if (fd == -1) {
	    	syslog(LOG_WARNING, "(mlfi_header) mkstemp failed, %d: %m", errno);
	    	(void)mlfi_cleanup (ctx, false);
	    	return SMFIS_TEMPFAIL;
		}
		priv->fileh = fdopen(fd, "w");

		if (!priv->fileh) {
	    	syslog(LOG_WARNING, "(mlfi_header) can't open tempfile, %d: %m", errno);
	    	(void)mlfi_cleanup(ctx, false);
	    	return SMFIS_TEMPFAIL;
		}
		/* fprintf (priv->fileh, "Received: from %s\n", priv->mlfi_ip_addr); */
    }

    /*
     * Write header line to temporary file.
     */

    fprintf (priv->fileh, "%s: %s\n", headerf, headerv);
    return SMFIS_CONTINUE;
}

static sfsistat 
mlfi_eoh(SMFICTX * ctx)
{
    struct mlfi_priv *priv = MLFIPRIV;
    fprintf (priv->fileh, "\n");
    return SMFIS_CONTINUE;
}

static sfsistat 
mlfi_eom(SMFICTX * ctx)
{
    struct mlfi_priv *priv = MLFIPRIV;
    int r;
    char strres[MAXPATHLEN], buf[MAXPATHLEN];
    char *id;

    /* set queue id */
    id = smfi_getsymval(ctx, "i");
    if (id == NULL) {
		id = "NOQUEUE";
	}
    strncpy (priv->mlfi_id, id, sizeof(priv->mlfi_id));

    syslog (LOG_WARNING, "%s: tempfile=%s", priv->mlfi_id, priv->file);

    fflush (priv->fileh);

    r = check_clamscan (priv->file, strres, MAXPATHLEN);
    if (r < 0) {
		syslog (LOG_WARNING, "(mlfi_eom, %s) check_clamscan() failed, %d", priv->mlfi_id, r);
		(void)mlfi_cleanup (ctx, false);
		return SMFIS_TEMPFAIL;
    }
    if (*strres) {
		syslog (LOG_WARNING, "(mlfi_eom, %s) rejecting virus %s", priv->mlfi_id, strres);
		snprintf (buf, MAXPATHLEN, "Infected: %s", strres);
		smfi_setreply (ctx, "554", "5.7.1", buf);
		mlfi_cleanup (ctx, false);
		return SMFIS_REJECT;
    }

    return mlfi_cleanup (ctx, true);
}

static sfsistat 
mlfi_close(SMFICTX * ctx)
{
    struct mlfi_priv *priv = MLFIPRIV;

    //syslog(LOG_WARNING, "(mlfi_close)");

    if (!priv) {
		return SMFIS_ACCEPT;
	}

    free(priv);
    smfi_setpriv(ctx, NULL);

    return SMFIS_ACCEPT;
}

static sfsistat 
mlfi_abort(SMFICTX * ctx)
{
    /* syslog(LOG_WARNING, "(mlfi_abort)"); */
    return mlfi_cleanup(ctx, false);
}

static sfsistat 
mlfi_cleanup(SMFICTX * ctx, bool ok)
{
    sfsistat rstat = SMFIS_CONTINUE;
    struct mlfi_priv *priv = MLFIPRIV;

    if (priv == NULL)  return rstat;

    if (ok) {
	/* add a header to the message announcing our presence */
	/* smfi_addheader(ctx, "X-Virus-Scanned", "clamav"); */
    }
    /* release message-related memory */
    priv->mlfi_id[0] = '\0';
    if (priv->fileh) {
		fclose (priv->fileh);
		priv->fileh = NULL;
    }
    if (priv->file) {
		unlink (priv->file);
		free(priv->file);
		priv->file = NULL;
    }
    /* return status */
    return rstat;
}

static sfsistat 
mlfi_body(SMFICTX * ctx, u_char * bodyp, size_t bodylen)
{
    struct mlfi_priv *priv = MLFIPRIV;

    if (fwrite (bodyp, bodylen, 1, priv->fileh) != 1) {
		syslog(LOG_WARNING, "(mlfi_body, %s) file write error, %d: %m", priv->mlfi_id, errno);
		(void)mlfi_cleanup(ctx, false);
		return SMFIS_TEMPFAIL;;
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
    struct stat sb;
    //syslog(LOG_WARNING, "(check_clamscan) %s", file);

    *strres = '\0';

    /* check file size */
    stat(file, &sb);
    if (sb.st_size > var_sizelimit) {
		syslog (LOG_WARNING, "(check_clamscan) message size exceeds limit, not scanned, %s", file);
		return 0;
    }
    /* scan using libclamc clamscan() */
    r = clamscan (file, var_clamd_socket, strres, strres_len);
 
    /* reset virusname for non-viruses */
    if (*strres && (!strcmp (strres, "Suspected.Zip") || !strcmp (strres, "Oversized.Zip"))) {
		*strres = '\0';
	}

    return r;
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

    if (!var_tempdir) {
		var_tempdir = getenv("TMPDIR");

	if (!var_tempdir)
	    var_tempdir = strdup("/tmp");
    }

    openlog("rmilter", LOG_PID, LOG_MAIL);
    syslog(LOG_WARNING, "(main) starting...");
	
	cfg = (struct config_file*) malloc (sizeof (struct config_file));
	if (cfg == NULL) {
		syslog (LOG_ERR, "malloc: %s", strerror (errno));
		return -1;
	}
	bzero (cfg, sizeof (struct config_file));

	LIST_INIT (&cfg->rules);
	LIST_INIT (&cfg->clamav_servers);
	
	if (cfg_file == NULL) {
		cfg_file = strdup ("/usr/local/etc/rmilter.conf");
	}

	f = fopen (cfg_file, "r");
	if (f == NULL) {
		syslog (LOG_ERR, "cannot open file: %s", cfg_file);
		return EBADF;
	}
	yyin = f;

	if (yyparse() != 0 || yynerrs > 0) {
		syslog (LOG_ERR, "yyparse: cannot parse config file, %d errors", yynerrs);
		return EBADF;
	}

    srandomdev();

    /*
     * Hack to set milter unix socket permissions, but it also affect
     * temporary file too :( temporary directory shuld be owned by user
     * rmilter-clam and have permissions 700
     */
    umask(0007);

	smfi_setconn(cfg->sock_cred);
	if (smfi_register(smfilter) == MI_FAILURE) {
		syslog(LOG_ERR, "smfi_register failed");
		exit(EX_UNAVAILABLE);
	}

    r = smfi_main();

    if (var_clamd_socket) {
		free(var_clamd_socket);
		var_clamd_socket = NULL;
    }

	if (cfg_file != NULL) free (cfg_file);

    return r;
}

/* eof */
