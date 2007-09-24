/*
 * $Id$
 */

#ifndef RMILTER_H
#define RMILTER_H

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "cfg_file.h"

#ifndef ADDRLEN
#define ADDRLEN 324
#endif

#ifndef NS_MAXDNAME
#define NS_MAXDNAME 1025
#endif

/* Structures and macros used */
struct rcpt {
	char r_addr[ADDRLEN + 1];
	LIST_ENTRY(rcpt) r_list;
};

struct header {
	char *h_line;
	TAILQ_ENTRY(header) h_list;
};

struct body {
	char *b_lines;
	TAILQ_ENTRY(body) b_list;
};

struct mlfi_priv {
	struct sockaddr_in priv_addr;
	char priv_hostname[ADDRLEN + 1];
	char priv_helo[ADDRLEN + 1];
	char priv_from[ADDRLEN + 1];
	LIST_HEAD(, rcpt) priv_rcpt;
	char *priv_cur_rcpt;
	int priv_rcptcount;
	TAILQ_HEAD(, header) priv_header;
	TAILQ_HEAD(, body) priv_body;
    char mlfi_id[32];
    char *file;
    FILE *fileh;
};

#define MLFIPRIV	((struct mlfi_priv *) smfi_getpriv(ctx))

#endif /* RMILTER_H */
