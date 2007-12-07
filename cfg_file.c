#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libmilter/mfapi.h>
#include <sys/queue.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <netdb.h>

#include "pcre.h"
#include "cfg_file.h"
#include "spf.h"

extern int yylineno;
extern char *yytext;

static size_t
copy_regexp (char **dst, const char *src)
{
	size_t len;
	if (!src || *src == '\0') return 0;

	len = strlen (src);

	/* Skip slashes */
	if (*src == '/') {
		src++;
		len--;
	}
	if (src[len - 1] == '/') {
		len--;
	}

	*dst = malloc (len + 1);
	if (!*dst) return 0;

	return strlcpy (*dst, src, len + 1);
}

int
add_memcached_server (struct config_file *cf, char *str)
{
	char *cur_tok, *err_str;
	struct memcached_server *mc;
	struct hostent *he;
	uint16_t port;

	if (str == NULL) return 0;

	cur_tok = strsep (&str, ":");

	if (cur_tok == NULL || *cur_tok == '\0') return 0;

	if(cf->memcached_servers_num == MAX_MEMCACHED_SERVERS) {
		yywarn ("yyparse: maximum number of memcached servers is reached %d", MAX_MEMCACHED_SERVERS);
	}
	
	mc = &cf->memcached_servers[cf->memcached_servers_num];
	if (mc == NULL) return 0;
	/* cur_tok - server name, str - server port */
	if (str == NULL) {
		port = htons(DEFAULT_MEMCACHED_PORT);
	}
	else {
		port = htons ((uint16_t)strtoul (str, &err_str, 10));
		if (*err_str != '\0') {
			return 0;
		}
	}

	if (!inet_aton (cur_tok, &mc->addr)) {
		/* Try to call gethostbyname */
		he = gethostbyname (cur_tok);
		if (he == NULL) {
			return 0;
		}
		else {
			memcpy((char *)&mc->addr, he->h_addr, sizeof(struct in_addr));
		}
	}
	mc->port = port;
	cf->memcached_servers_num++;
	return 1;
}

int
add_clamav_server (struct config_file *cf, char *str)
{
	char *cur_tok, *err_str;
	struct clamav_server *srv;
	struct hostent *he;
	size_t s;

	if (str == NULL) return 0;
	
	cur_tok = strsep (&str, ":");
	
	if (cur_tok == NULL || *cur_tok == '\0') return 0;

	if (cf->clamav_servers_num == MAX_CLAMAV_SERVERS) {
		yywarn ("yyparse: maximum number of clamav servers is reached %d", MAX_CLAMAV_SERVERS);
	}

	srv = &cf->clamav_servers[cf->clamav_servers_num];

	if (srv == NULL) return 0;

	if (cur_tok[0] == '/' || cur_tok[0] == '.') {
		srv->sock.unix_path = strdup (cur_tok);
		srv->sock_type = AF_UNIX;
		srv->name = srv->sock.unix_path;

		cf->clamav_servers_num++;
		return 1;

	} else {
		if (str == '\0') {
			srv->sock.inet.port = htons (DEFAULT_CLAMAV_PORT);
		}
		else {
			srv->sock.inet.port = htons ((uint16_t)strtoul (str, &err_str, 10));
			if (*err_str != '\0') {
				return 0;
			}
		}

		if (!inet_aton (cur_tok, &srv->sock.inet.addr)) {
			/* Try to call gethostbyname */
			he = gethostbyname (cur_tok);
			if (he == NULL) {
				return 0;
			}
			else {
				srv->name = strdup (cur_tok);
				memcpy((char *)&srv->sock.inet.addr, he->h_addr, sizeof(struct in_addr));
				s = strlen (cur_tok) + 1;
			}
		}

		srv->sock_type = AF_INET;
		cf->clamav_servers_num++;
		return 1;
	}

	return 0;
}

struct action *
create_action (enum action_type type, const char *message)
{
	struct action *new;
	size_t len = strlen (message);

	if (message == NULL) return NULL;

	new = (struct action *)malloc (sizeof (struct action)); 

	if (new == NULL) return NULL;

	new->type = type;
	/* Trim quotes */
	if (*message == '"') {
		message++;
		len--;
	}
	if (message[len - 1] == '"') {
		len--;
	}

	new->message = (char *)malloc (len + 1);

	if (new->message == NULL) return NULL;

	strlcpy (new->message, message, len + 1);

	return new;
}

struct condition *
create_cond (enum condition_type type, const char *arg1, const char *arg2)
{
	struct condition *new;
	int offset;
	const char *read_err;

	new = (struct condition *)malloc (sizeof (struct condition));
	bzero (new, sizeof (struct condition));
	
	if (new == NULL) return NULL;

	if (arg1 == NULL || *arg1 == '\0') {
		new->args[0].empty = 1;
	}
	else {
		if (!copy_regexp (&new->args[0].src, arg1)) {
			new->args[0].empty = 1;
		}
		else {
			new->args[0].re = pcre_compile (new->args[0].src, 0, &read_err, &offset, NULL);
			if (new->args[0].re == NULL) {
				new->args[0].empty = 1;
			}
		}
	}
	if (arg2 == NULL || *arg2 == '\0') {
		new->args[1].empty = 1;
	}
	else {
		if (!copy_regexp (&new->args[1].src, arg2)) {
			new->args[1].empty = 1;
		}
		else {
			new->args[1].re = pcre_compile (new->args[1].src, 0, &read_err, &offset, NULL);
			if (new->args[1].re == NULL) {
				new->args[1].empty = 1;
			}
		}
	}

	new->type = type;

	return new;
}

int
add_spf_domain (struct config_file *cfg, char *domain)
{
	if (!domain) return 0;

	if (cfg->spf_domains_num > MAX_SPF_DOMAINS) {
		return 0;
	}

	cfg->spf_domains[cfg->spf_domains_num] = domain;
	cfg->spf_domains_num ++;

	return 1;
}

void
init_defaults (struct config_file *cfg)
{
	LIST_INIT (&cfg->rules);
	LIST_INIT (&cfg->whitelist_ip);
	LIST_INIT (&cfg->whitelist_rcpt);
	LIST_INIT (&cfg->bounce_addrs);

	cfg->clamav_connect_timeout = DEFAULT_CLAMAV_CONNECT_TIMEOUT;
	cfg->clamav_port_timeout = DEFAULT_CLAMAV_PORT_TIMEOUT;
	cfg->clamav_results_timeout = DEFAULT_CLAMAV_RESULTS_TIMEOUT;
	cfg->memcached_connect_timeout = DEFAULT_MEMCACHED_CONNECT_TIMEOUT;

	cfg->clamav_error_time = DEFAULT_UPSTREAM_ERROR_TIME;
	cfg->clamav_dead_time = DEFAULT_UPSTREAM_DEAD_TIME;
	cfg->clamav_maxerrors = DEFAULT_UPSTREAM_MAXERRORS;

	cfg->memcached_error_time = DEFAULT_UPSTREAM_ERROR_TIME;
	cfg->memcached_dead_time = DEFAULT_UPSTREAM_DEAD_TIME;
	cfg->memcached_maxerrors = DEFAULT_UPSTREAM_MAXERRORS;
	cfg->memcached_protocol = UDP_TEXT;

	cfg->spf_domains = (char **) calloc (MAX_SPF_DOMAINS, sizeof (char *));
}
