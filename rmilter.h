/*
 * $Id$
 */

#ifndef RMILTER_H
#define RMILTER_H

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include "cfg_file.h"

#ifndef ADDRLEN
#define ADDRLEN 324
#endif

#ifndef NS_MAXDNAME
#define NS_MAXDNAME 1025
#endif

/* Logging in postfix style */
#if __ISO_C_VISIBLE >= 1999
#define msg_err(args...) syslog(LOG_ERR, ##args)
#define msg_warn(args...)	syslog(LOG_WARNING, ##args)
#define msg_info(args...)	syslog(LOG_INFO, ##args)
#else
#error Need to be compiled with C99 compatible compiler
#endif

#define RCODE_REJECT    "554"
#define RCODE_TEMPFAIL  "451"
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
	char *priv_cur_rcpt;
	int priv_rcptcount;
	struct {
		char *header_name;
		char *header_value;
	} priv_cur_header;
	char *priv_cur_body;
    char mlfi_id[32];
    char *file;
    FILE *fileh;
};

#define MLFIPRIV	((struct mlfi_priv *) smfi_getpriv(ctx))

#endif /* RMILTER_H */
