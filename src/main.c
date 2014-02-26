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
#include "cfg_file.h"
#include "rmilter.h"

/* config options here... */

struct config_file *cfg;
extern struct smfiDesc smfilter;

pthread_cond_t cfg_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t cfg_reload_mtx = PTHREAD_MUTEX_INITIALIZER;
/* R/W lock for reconfiguring milter */
pthread_rwlock_t cfg_mtx = PTHREAD_RWLOCK_INITIALIZER;

int
my_strcmp (const void *s1, const void *s2)
{
	return strcmp (*(const char **)s1, *(const char **)s2);
}

static void 
usage (void)
{
	printf ("Rapid Milter Version " MVERSION "\n"
			"Usage: rmilter [-h] -c <config_file>\n"
			"-h - this help message\n"
			"-c - path to config file\n");
	exit (0);
}

static void
sig_usr1_handler (int signo)
{
	pthread_cond_signal(&cfg_cond);
}

static void *
reload_thread (void *unused)
{
	extern int yynerrs;
	extern FILE *yyin;
	FILE *f;
	struct config_file *new_cfg = NULL, *tmp;
	struct sigaction signals;

	/* Initialize signals and start reload thread */
	bzero (&signals, sizeof (struct sigaction));
	sigemptyset(&signals.sa_mask);
    sigaddset(&signals.sa_mask, SIGUSR1);
	signals.sa_handler = sig_usr1_handler;
	sigaction (SIGUSR1, &signals, NULL);

	msg_info ("reload_thread: starting...");

	/* lock on mutex until we got SIGUSR1 that unlocks mutex */
	while (1) {
		pthread_mutex_lock(&cfg_reload_mtx);
		pthread_cond_wait(&cfg_cond, &cfg_reload_mtx);
		pthread_mutex_unlock(&cfg_reload_mtx);
		msg_warn ("reload_thread: reloading, rmilter version %s", MVERSION);
		/* lock for writing */
		CFG_WLOCK();
		f = fopen (cfg->cfg_name, "r");

		if (f == NULL) {
			CFG_UNLOCK();
			msg_warn ("reload_thread: cannot open file %s, %m", cfg->cfg_name);
			continue;
		}

		new_cfg = (struct config_file*) malloc (sizeof (struct config_file));
		if (new_cfg == NULL) {
			CFG_UNLOCK();
			fclose (f);
			msg_warn ("reload_thread: malloc, %s", strerror (errno));
			continue;
		}

		bzero (new_cfg, sizeof (struct config_file));
		init_defaults (new_cfg);
		new_cfg->cfg_name = cfg->cfg_name;
		tmp = cfg;
		cfg = new_cfg;

		yyin = f;
		yyrestart (yyin);

		if (yyparse() != 0 || yynerrs > 0) {
			CFG_UNLOCK();
			fclose (f);
			msg_warn ("reload_thread: cannot parse config file %s", cfg->cfg_name);
			free_config (new_cfg);
			free (new_cfg);
			cfg = tmp;
			continue;
		}

		fclose (f);
		new_cfg->cfg_name = tmp->cfg_name;
		new_cfg->serial = tmp->serial + 1;
		
		/* Strictly set temp dir */
		if (!cfg->temp_dir) {
			msg_warn ("tempdir is not set, trying to use $TMPDIR");
			cfg->temp_dir = getenv("TMPDIR");

			if (!cfg->temp_dir) {
				cfg->temp_dir = strdup("/tmp");
			}
		}
		/* Sort spf domains array */
		qsort ((void *)cfg->spf_domains, cfg->spf_domains_num, sizeof (char *), my_strcmp);
		/* Init awl */
		if (cfg->awl_enable) {
			cfg->awl_hash = awl_init (cfg->awl_pool_size, cfg->awl_max_hits, cfg->awl_ttl);
			if (cfg->awl_hash == NULL) {
				msg_warn ("cannot init awl");
				cfg->awl_enable = 0;
			}
		}
#ifdef HAVE_SRANDOMDEV
   		srandomdev();
#else
		srand (time (NULL));
#endif
		/* Free old config */
		free_config (tmp);
		free (tmp);

		CFG_UNLOCK();
	}
	return NULL;
}

int 
main(int argc, char *argv[])
{
    int c, r;
	extern int yynerrs;
	extern FILE *yyin;
    const char *args = "c:h";
	char *cfg_file = NULL;
	FILE *f;
	pthread_t reload_thr;

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
    msg_warn ("main: starting rmilter version %s", MVERSION);
	
	cfg = (struct config_file*) malloc (sizeof (struct config_file));
	if (cfg == NULL) {
		msg_warn ("malloc: %s", strerror (errno));
		return -1;
	}
	bzero (cfg, sizeof (struct config_file));
	init_defaults (cfg);
		
	if (cfg_file == NULL) {
		cfg_file = strdup ("/usr/local/etc/rmilter.conf");
	}

	f = fopen (cfg_file, "r");
	if (f == NULL) {
		msg_warn ("cannot open file: %s", cfg_file);
		return EBADF;
	}
	yyin = f;
	
	yyrestart (yyin);

	if (yyparse() != 0 || yynerrs > 0) {
		msg_warn ("yyparse: cannot parse config file, %d errors", yynerrs);
		return EBADF;
	}

	fclose (f);
	cfg->cfg_name = strdup (cfg_file);

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

	/* Init awl */
	if (cfg->awl_enable) {
		cfg->awl_hash = awl_init (cfg->awl_pool_size, cfg->awl_max_hits, cfg->awl_ttl);
		if (cfg->awl_hash == NULL) {
			msg_warn ("cannot init awl");
			cfg->awl_enable = 0;
		}
	}

#ifdef HAVE_SRANDOMDEV
   	srandomdev();
#else
	srand (time (NULL));
#endif

	/* Set unix socket permissions if specified in config */
	if (cfg->sock_cred_mode)
        	umask(0777 & ~cfg->sock_cred_mode);

	smfi_setconn(cfg->sock_cred);
	if (smfi_register(smfilter) == MI_FAILURE) {
		msg_err ("smfi_register failed");
		exit(EX_UNAVAILABLE);
	}

	if (pthread_create (&reload_thr, NULL, reload_thread, NULL)) {
		msg_warn ("main: cannot start reload thread, ignoring error");
	}

    r = smfi_main();

	if (cfg_file != NULL) free (cfg_file);

    return r;
}

/* 
 * vi:ts=4 
 */
