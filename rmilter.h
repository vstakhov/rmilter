/*
 * $Id$
 */

#ifndef RMILTER_H
#define RMILTER_H

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <stdio.h>
#include <netinet/in.h>
#include <time.h>
#include "cfg_file.h"

#ifndef ADDRLEN
#define ADDRLEN 324
#endif

#ifndef NS_MAXDNAME
#define NS_MAXDNAME 1025
#endif

/* Logging in postfix style */
#define msg_err(args...) syslog(LOG_ERR, ##args)
#define msg_warn(args...)	syslog(LOG_WARNING, ##args)
#define msg_info(args...)	syslog(LOG_INFO, ##args)
#define msg_debug(args...) syslog(LOG_DEBUG, ##args)

#define RCODE_REJECT    "554"
#define RCODE_TEMPFAIL  "451"
#define RCODE_LATER  	"452"
#define XCODE_REJECT    "5.7.1"
#define XCODE_TEMPFAIL  "4.7.1"

/* Structures and macros used */
struct rcpt {
	char r_addr[ADDRLEN + 1];
	LIST_ENTRY(rcpt) r_list;
};

struct mlfi_priv {
	struct sockaddr_in priv_addr;
	char priv_ip[INET_ADDRSTRLEN + 1];
	char priv_hostname[ADDRLEN + 1];
	char priv_helo[ADDRLEN + 1];
	char priv_from[ADDRLEN + 1];
	char priv_rcpt[ADDRLEN + 1];
	char *priv_cur_rcpt;
	int priv_rcptcount;
	struct {
		char *header_name;
		char *header_value;
	} priv_cur_header;
	struct {
		char *value;
		size_t len;
	} priv_cur_body;
    char mlfi_id[32];
    char file[PATH_MAX];
    FILE *fileh;
	int filed;
	struct timeval conn_tm;
};

#define MLFIPRIV	((struct mlfi_priv *) smfi_getpriv(ctx))

#endif /* RMILTER_H */
/* 
 * vi:ts=4 
 */
