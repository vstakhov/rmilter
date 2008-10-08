/*
 * $Id$
 */

#ifndef RMILTER_H
#define RMILTER_H

#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifndef OWN_QUEUE_H
#include <sys/queue.h>
#else
#include "queue.h"
#endif
#include <sys/socket.h>
#include <sys/param.h>
#include <stdio.h>
#include <netinet/in.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_STRLCPY_H
#include "strlcpy.h"
#endif

#include "cfg_file.h"

#ifndef ADDRLEN
#define ADDRLEN 324
#endif

#ifndef NS_MAXDNAME
#define NS_MAXDNAME 1025
#endif

#define STAGE_MAX 7

/* Logging in postfix style */
#define msg_err(args...) syslog(LOG_ERR, ##args)
#define msg_warn(args...)	syslog(LOG_WARNING, ##args)
#define msg_info(args...)	syslog(LOG_INFO, ##args)
#ifdef WITH_DEBUG
#define msg_debug(args...) syslog(LOG_DEBUG, ##args)
#else
#define msg_debug(args...) do {} while(0)
#endif

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
	char reply_id[ADDRLEN + 33];
	#ifdef HAVE_PATH_MAX
	char file[PATH_MAX];
#elif defined(HAVE_MAXPATHLEN)
	char file[MAXPATHLEN];
#else
#error "neither PATH_MAX nor MAXPATHLEN defined"
#endif
    FILE *fileh;
	int filed;
	struct timeval conn_tm;
	struct rule* matched_rules[STAGE_MAX];
	short int strict;
	/* Config serial */
	short int serial;
	short int has_return_path;
};

#define MLFIPRIV	((struct mlfi_priv *) smfi_getpriv(ctx))

#endif /* RMILTER_H */
/* 
 * vi:ts=4 
 */
