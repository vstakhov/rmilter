/* $Id$ */

%{

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

#define yyerror(fmt, ...) syslog (LOG_ERR, fmt, ##__VA_ARGS__)
#define YYDEBUG 0

extern struct config_file *cfg;

struct condl *cur_conditions;
uint8_t cur_flags = 0;

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

static int
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
		yyerror ("yyparse: maximum number of memcached servers is reached %d", MAX_MEMCACHED_SERVERS);
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
	printf ("Shit2\n");
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

static int
add_clamav_server (struct config_file *cf, char *str)
{
	char *cur_tok, *host_tok, *err_str;
	struct clamav_server *srv;
	struct hostent *he;
	size_t s;

	if (str == NULL) return 0;
	
	cur_tok = strsep (&str, ":@");

	if (str == NULL || cur_tok == NULL || *cur_tok == '\0') return 0;

	if (cf->clamav_servers_num == MAX_CLAMAV_SERVERS) {
		yyerror ("yyparse: maximum number of clamav servers is reached %d", MAX_CLAMAV_SERVERS);
	}

	srv = &cf->clamav_servers[cf->clamav_servers_num];

	if (srv == NULL) return 0;

	if (strncmp (cur_tok, "local", sizeof ("local")) == 0 ||
		strncmp (cur_tok, "unix", sizeof ("unix")) == 0) {
		srv->sock.unix_path = strdup (str);
		srv->sock_type = AF_UNIX;
		srv->active = 1;

		cf->clamav_servers_num++;
		return 1;
	} else if (strncmp (cur_tok, "inet", sizeof ("inet")) == 0) {
		host_tok = strsep (&str, "@");
		srv->sock.inet.port = htons ((uint16_t)strtoul (host_tok, &err_str, 10));
		if (*err_str != '\0') {
			return 0;
		}

		if (!host_tok || !str) {
			return 0;
		}
		else {
			if (!inet_aton (str, &srv->sock.inet.addr)) {
				/* Try to call gethostbyname */
				he = gethostbyname (str);
				if (he == NULL) {
					return 0;
				}
				else {
					memcpy((char *)&srv->sock.inet.addr, he->h_addr, sizeof(struct in_addr));
					s = strlen (str) + 1;
					srv->sock.inet.addr_str = (char *)malloc (s);
					strlcpy (srv->sock.inet.addr_str, str, s);
				}
			}
		}

		srv->sock_type = AF_INET;
		srv->active = 1;
		cf->clamav_servers_num++;
		return 1;
	}

	return 0;
}

static struct action *
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

static struct condition *
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

static int
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

%}
%union 
{
	char *string;
	struct condition *cond;
	struct action *action;
	size_t limit;
	char flag;
}

%token	ERROR STRING QUOTEDSTRING FLAG
%token	ACCEPT REJECTL TEMPFAIL DISCARD QUARANTINE
%token	CONNECT HELO ENVFROM ENVRCPT HEADER MACRO BODY
%token	AND OR NOT
%token  TEMPDIR LOGFILE PIDFILE RULE CLAMAV SPF DCC
%token  FILENAME REGEXP QUOTE SEMICOLON OBRACE EBRACE COMMA EQSIGN
%token  BINDSOCK SOCKCRED DOMAIN
%token  MAXSIZE LIMIT USEDCC MEMCACHED MEMC_SRV
%type	<string>	STRING
%type	<string>	QUOTEDSTRING
%type	<string>	FILENAME
%type	<string>	REGEXP
%type   <string>  	SOCKCRED
%type	<string>	MEMC_SRV
%type 	<string>	memcached_hosts
%type   <cond>    	expr_l expr term
%type   <action>  	action
%type	<string>	DOMAIN
%type	<limit>		LIMIT
%type	<flag>		FLAG
%%

file	: /* empty */
	|  file command SEMICOLON { }
	;

command	: 
	tempdir
	| pidfile
	| rule
	| clamav
	| spf
	| bindsock
	| maxsize
	| usedcc
	| memcached
	;

tempdir :
	TEMPDIR EQSIGN FILENAME {
		cfg->temp_dir = $3;
	}
	;

pidfile :
	PIDFILE EQSIGN FILENAME {
		cfg->pid_file = $3;
	}
	;

rule	: 
		RULE OBRACE rulebody EBRACE
		;

rulebody	: 
			action SEMICOLON expr_l {
				struct rule *cur_rule;
				cur_rule = (struct rule *) malloc (sizeof (struct rule));
				if (cur_rule == NULL) {
					yyerror ("yyparse: malloc: %s", strerror (errno));
					YYERROR;
				}

				cur_rule->act = $1;
				cur_rule->conditions = cur_conditions;
				cur_rule->flags = cur_flags;
				cur_flags = 0;
				LIST_INSERT_HEAD (&cfg->rules, cur_rule, next);
			}
			;

action	: 
	REJECTL QUOTEDSTRING {
		$$ = create_action(ACTION_REJECT, $2);
		if ($$ == NULL) {
			yyerror ("yyparse: create_action");
			YYERROR;
		}
		free($2);
	}
	| TEMPFAIL QUOTEDSTRING {
		$$ = create_action(ACTION_TEMPFAIL, $2);
		if ($$ == NULL) {
			yyerror ("yyparse: create_action");
			YYERROR;
		}
		free($2);
	}
	| QUARANTINE QUOTEDSTRING	{
		$$ = create_action(ACTION_QUARANTINE, $2);
		if ($$ == NULL) {
			yyerror ("yyparse: create_action");
			YYERROR;
		}
		free($2);
	}
	| DISCARD {
		$$ = create_action(ACTION_DISCARD, "");
		if ($$ == NULL) {
			yyerror ("yyparse: create_action");
			YYERROR;
		}
	}
	| ACCEPT {
		$$ = create_action(ACTION_ACCEPT, "");
		if ($$ == NULL) {
			yyerror ("yyparse: create_action");
			YYERROR;
		}
	}
	;

expr_l	: 
	expr SEMICOLON		{
		cur_conditions = (struct condl *)malloc (sizeof (struct condl));
		if (cur_conditions == NULL) {
			yyerror ("yyparse: malloc: %s", strerror (errno));
			YYERROR;
		}
		LIST_INIT (cur_conditions);
		$$ = $1;
		if ($$ == NULL) {
			yyerror ("yyparse: malloc: %s", strerror(errno));
			YYERROR;
		}
		LIST_INSERT_HEAD (cur_conditions, $$, next);
	}
	| expr_l expr	{
		$$ = $2;
		if ($$ == NULL) {
			yyerror ("yyparse: malloc: %s", strerror(errno));
			YYERROR;
		}
		LIST_INSERT_HEAD (cur_conditions, $$, next);
	}
	;

expr	: 
	term			{
		$$ = $1;
	}
	| NOT term		{
		struct condition *tmp;
		tmp = $2;
		if (tmp != NULL) {
			tmp->args[0].not = 1;
			tmp->args[1].not = 1;
		}
		$$ = tmp;
	}
	;

term	: 
	CONNECT REGEXP REGEXP	{
		$$ = create_cond(COND_CONNECT, $2, $3);
		if ($$ == NULL) {
			yyerror ("yyparse: malloc: %s", strerror(errno));
			YYERROR;
		}
		cur_flags |= COND_CONNECT_FLAG;
		free($2);
		free($3);
	}
	| HELO REGEXP		{
		$$ = create_cond(COND_HELO, $2, NULL);
		if ($$ == NULL) {
			yyerror ("yyparse: malloc: %s", strerror(errno));
			YYERROR;
		}
		cur_flags |= COND_HELO_FLAG;
		free($2);
	}
	| ENVFROM REGEXP	{
		$$ = create_cond(COND_ENVFROM, $2, NULL);
		if ($$ == NULL) {
			yyerror ("yyparse: malloc: %s", strerror(errno));
			YYERROR;
		}
		cur_flags |= COND_ENVFROM_FLAG;
		free($2);
	}
	| ENVRCPT REGEXP	{
		$$ = create_cond(COND_ENVRCPT, $2, NULL);
		if ($$ == NULL) {
			yyerror ("yyparse: malloc: %s", strerror(errno));
			YYERROR;
		}
		cur_flags |= COND_ENVRCPT_FLAG;
		free($2);
	}
	| HEADER REGEXP REGEXP	{
		$$ = create_cond(COND_HEADER, $2, $3);
		if ($$ == NULL) {
			yyerror ("yyparse: malloc: %s", strerror(errno));
			YYERROR;
		}
		cur_flags |= COND_HEADER_FLAG;
		free($2);
		free($3);
	}
	| BODY REGEXP		{
		$$ = create_cond(COND_BODY, $2, NULL);
		if ($$ == NULL) {
			yyerror ("yyparse: malloc: %s", strerror(errno));
			YYERROR;
		}
		cur_flags |= COND_BODY_FLAG;
		free($2);
	}
	;

clamav:
	CLAMAV EQSIGN clamav_params
	;

clamav_params:
	clamav_server
	| clamav_params COMMA clamav_server
	;

clamav_server:
	SOCKCRED	{
		if (!add_clamav_server (cfg, $1)) {
			yyerror ("yyparse: add_clamav_server");
			YYERROR;
		}
		free ($1);
	}
	;

spf:
	SPF EQSIGN spf_params 
	;
spf_params:
	spf_domain
	| spf_params COMMA spf_domain
	;

spf_domain:
	DOMAIN {
		if (!add_spf_domain (cfg, $1)) {
			yyerror ("yyparse: add_spf_domain");
			YYERROR;
		}
	}
	;

bindsock:
	BINDSOCK EQSIGN SOCKCRED {
		cfg->sock_cred = $3;
	}
	;

maxsize:
	MAXSIZE EQSIGN LIMIT {
		cfg->sizelimit = $3;
	}
	;
usedcc:
	USEDCC EQSIGN FLAG {
		if ($3 == -1) {
			yyerror ("yyparse: parse flag");
			YYERROR;
		}
		cfg->use_dcc = $3;
	}
memcached:
	MEMCACHED EQSIGN memcached_params
	;

memcached_params:
	memcached_server
	| memcached_params COMMA memcached_server
	;

memcached_server:
	memcached_hosts {
		if (!add_memcached_server (cfg, $1)) {
			yyerror ("yyparse: add_memcached_server");
			YYERROR;
		}
		free ($1);
	}
	;
memcached_hosts:
	STRING
	| MEMC_SRV
	;
%%
