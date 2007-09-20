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

/* pthread_mutex_t mx_whoson = PTHREAD_MUTEX_INITIALIZER; */

/* Structures and macros used */

struct mlfiPriv {
    char mlfi_ip_addr[sizeof("255.255.255.255")];
    char mlfi_id[32];
    char *file;
    FILE *fileh;
};

#define MLFIPRIV	((struct mlfiPriv *) smfi_getpriv(ctx))

extern sfsistat mlfi_cleanup(SMFICTX *, bool);
extern int check_clamscan(const char *file, char *strres, size_t strres_len);

static void usage (void)
{
	printf ("Usage: rmilter [-h] -c <config_file>\n"
			"-h - this help message\n"
			"-c - path to config file\n");
	exit (0);
}

/* Milter callbacks */

sfsistat mlfi_connect(SMFICTX * ctx, char *hostname, _SOCK_ADDR * hostaddr)
{
    struct mlfiPriv *priv;

    priv = malloc(sizeof *priv);
    if (priv == NULL) {
	return SMFIS_TEMPFAIL;
    }
    memset(priv, '\0', sizeof *priv);

    /*
     * According to the sendmail API hostaddr is NULL if "the type is not
     * supported in the current version". What the documentation doesn't say
     * is the type of what.
     */

    strlcpy(priv->mlfi_ip_addr, "NULL", sizeof(priv->mlfi_ip_addr));
    if ((hostaddr == NULL) || (&(((struct sockaddr_in *)(hostaddr))->sin_addr) == NULL))
	syslog(LOG_WARNING, "(mlfi_connect) hostaddr is NULL");
    else
	(void)inet_ntop(AF_INET, &((struct sockaddr_in *)(hostaddr))->sin_addr,
			priv->mlfi_ip_addr, sizeof(priv->mlfi_ip_addr));

    //syslog(LOG_WARNING, "(mlfi_connect) ip: %s", priv->mlfi_ip_addr);

    smfi_setpriv(ctx, priv);

    return SMFIS_CONTINUE;
}

sfsistat mlfi_header(SMFICTX * ctx, char *headerf, char *headerv)
{
    struct mlfiPriv *priv = MLFIPRIV;
    char buf[MAXPATHLEN];
    int fd;

    /*
     * Create temporary file, if this is first call of mlfi_header(), and it
     * not yet created
     */

    if (!priv->fileh) {
	snprintf(buf, MAXPATHLEN, "%s/msg.XXXXXXXX", var_tempdir);
	priv->file = strdup(buf);
	/* XXX: mkstemp(3) not thread-safe, may be */
	fd = mkstemp(priv->file);
	if (fd == -1) {
	    syslog(LOG_WARNING, "(mlfi_header) mkstemp failed, %d: %m", errno);
	    (void)mlfi_cleanup(ctx, false);
	    return SMFIS_TEMPFAIL;
	}
	priv->fileh = fdopen(fd, "w");
	if (!priv->fileh) {
	    syslog(LOG_WARNING, "(mlfi_header) can't open tempfile, %d: %m", errno);
	    (void)mlfi_cleanup(ctx, false);
	    return SMFIS_TEMPFAIL;
	}
	fprintf(priv->fileh, "Received: from %s\n", priv->mlfi_ip_addr);
    }

    /*
     * Write header line to temporary file.
     */

    fprintf(priv->fileh, "%s: %s\n", headerf, headerv);
    return SMFIS_CONTINUE;
}

sfsistat mlfi_eoh(SMFICTX * ctx)
{
    struct mlfiPriv *priv = MLFIPRIV;
    fprintf(priv->fileh, "\n");
    return SMFIS_CONTINUE;
}

sfsistat mlfi_eom(SMFICTX * ctx)
{
    struct mlfiPriv *priv = MLFIPRIV;
    int r;
    char strres[MAXPATHLEN], buf[MAXPATHLEN];
    char *id;

    /* set queue id */
    id = smfi_getsymval(ctx, "i");
    if (id == NULL)
	id = "NOQUEUE";
    strncpy(priv->mlfi_id, id, sizeof(priv->mlfi_id));

    syslog(LOG_WARNING, "%s: tempfile=%s", priv->mlfi_id, priv->file);

    fflush(priv->fileh);

    r = check_clamscan(priv->file, strres, MAXPATHLEN);
    if (r < 0) {
	syslog(LOG_WARNING, "(mlfi_eom, %s) check_clamscan() failed, %d", priv->mlfi_id, r);
	(void)mlfi_cleanup(ctx, false);
	return SMFIS_TEMPFAIL;
    }
    if (*strres) {
	syslog(LOG_WARNING, "(mlfi_eom, %s) rejecting virus %s", priv->mlfi_id, strres);
	snprintf(buf, MAXPATHLEN, "Infected: %s", strres);
	smfi_setreply(ctx, "554", "5.7.1", buf);
	mlfi_cleanup(ctx, false);
	return SMFIS_REJECT;
    }
    return mlfi_cleanup(ctx, true);
}

sfsistat mlfi_close(SMFICTX * ctx)
{
    struct mlfiPriv *priv = MLFIPRIV;

    //syslog(LOG_WARNING, "(mlfi_close)");

    if (!priv)
	return SMFIS_ACCEPT;

    free(priv);
    smfi_setpriv(ctx, NULL);

    return SMFIS_ACCEPT;
}

sfsistat mlfi_abort(SMFICTX * ctx)
{
    /* syslog(LOG_WARNING, "(mlfi_abort)"); */
    return mlfi_cleanup(ctx, false);
}

sfsistat mlfi_cleanup(SMFICTX * ctx, bool ok)
{
    sfsistat rstat = SMFIS_CONTINUE;
    struct mlfiPriv *priv = MLFIPRIV;

    /*
     * syslog(LOG_WARNING, "(mlfi_cleanup)");
     */

    if (priv == NULL)
	return rstat;

    if (ok) {
	/* add a header to the message announcing our presence */
	/* smfi_addheader(ctx, "X-Virus-Scanned", "clamav"); */
    }
    /* release message-related memory */
    priv->mlfi_id[0] = '\0';
    if (priv->fileh) {

	/*
	 * syslog(LOG_WARNING, "(mlfi_cleanup) fclose");
	 */
	fclose(priv->fileh);
	priv->fileh = NULL;
    }
    if (priv->file) {
	unlink(priv->file);
	free(priv->file);
	priv->file = NULL;
    }
    /* return status */
    return rstat;
}

sfsistat mlfi_body(SMFICTX * ctx, u_char * bodyp, size_t bodylen)
{
    struct mlfiPriv *priv = MLFIPRIV;

    if (fwrite(bodyp, bodylen, 1, priv->fileh) != 1) {
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

int check_clamscan(const char *file, char *strres, size_t strres_len)
{
    int r = -2;
    struct stat sb;
    //syslog(LOG_WARNING, "(check_clamscan) %s", file);

    *strres = '\0';

    /* check file size */
    stat(file, &sb);
    if (sb.st_size > var_sizelimit) {
	syslog(LOG_WARNING, "(check_clamscan) message size exceeds limit, not scanned, %s", file);
	return 0;
    }
    /* scan using libclamc clamscan() */
    r = clamscan(file, var_clamd_socket, strres, strres_len);

    /* reset virusname for non-viruses */
    if (*strres && (!strcmp(strres, "Suspected.Zip") || !strcmp(strres, "Oversized.Zip")))
	*strres = '\0';

    return r;
}



/*****************************************************************************/



int main(int argc, char *argv[])
{
    int c, r;
	extern int yynerrs;
    const char *args = "c:h";
	struct smfiDesc smfilter =
	{
    	"rmilter",			/* filter name */
    	SMFI_VERSION,		/* version code -- do not change */
    	SMFIF_ADDHDRS,		/* flags */
    	mlfi_connect,		/* connection info filter */
    	NULL,				/* SMTP HELO command filter */
    	NULL,				/* envelope sender filter */
    	NULL,				/* envelope recipient filter */
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
				fprintf(stderr, "Illegal conn: %s\n",
			      optarg);
				exit(EX_USAGE);
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

	if (!yyparse() || yynerrs > 0) {
		syslog (LOG_ERR, "yyparse: cannot parse config file");
		return -1;
	}

    srandomdev();

    /*
     * Hack to set milter unix socket permissions, but it also affect
     * temporary file too :( temporary directory shuld be owned by user
     * rmilter-clam and have permissions 700
     */
    umask(0007);

    r = smfi_main();

    if (var_clamd_socket) {
	free(var_clamd_socket);
	var_clamd_socket = NULL;
    }
    return r;
}

/* eof */
