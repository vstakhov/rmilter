/*
 * $Id$
 */


#ifndef CFG_FILE_H
#define CFG_FILE_H

#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <sys/un.h>
#include "pcre.h"

enum { VAL_UNDEF=0, VAL_TRUE, VAL_FALSE };
enum condition_type { 
	COND_CONNECT, 
	COND_HELO, 
	COND_ENVFROM, 
	COND_ENVRCPT,
	COND_HEADER, 
	COND_BODY, 
	COND_MAX 
};

enum action_type { 
	ACTION_REJECT, 
	ACTION_TEMPFAIL, 
	ACTION_QUARANTINE, 
	ACTION_DISCARD, 
	ACTION_ACCEPT 
};

struct action {
	enum action_type type;
	char *message;
};

struct condition {
    struct cond_arg {
    	char    *src;
    	int  empty;
    	int  not;
	    pcre  *re;
    }	args[2];
	LIST_ENTRY (condition) next;
};

struct rule {
	LIST_HEAD (condl, condition) *conditions;
	struct action *act;
	LIST_ENTRY (rule) next;
};

struct clamav_server {
	int sock_type;

	union {
		char *unix_path;
		struct {
			struct in_addr addr;
			uint16_t port;
		} inet;
	} sock;
	LIST_ENTRY (clamav_server) next;
};

struct config_file {
	char *pid_file;
	char *temp_dir;

	char *spf_file;

	char *sock_cred;

	LIST_HEAD (ruleset, rule) rules;
	LIST_HEAD (clamavl, clamav_server) clamav_servers;
};

int yylex (void);
int yyparse (void);

#endif /* ifdef CFG_FILE_H */
