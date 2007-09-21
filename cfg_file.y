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

#include "pcre.h"
#include "cfg_file.h"
#include "spf.h"

#define yyerror(fmt, ...) syslog (LOG_ERR, fmt, ##__VA_ARGS__)
#define YYDEBUG 0

extern struct config_file *cfg;

struct condl *cur_conditions;

static int
add_clamav_server (struct config_file *cf, char *str)
{
	char *cur_tok, *host_tok, *err_str;
	struct clamav_server *srv;

	if (str == NULL) return 0;
	
	cur_tok = strsep (&str, ":@");

	if (str == NULL || cur_tok == NULL || *cur_tok == '\0') return 0;

	srv = (struct clamav_server *) malloc (sizeof (struct clamav_server));
	bzero (srv, sizeof (struct clamav_server));

	if (srv == NULL) return 0;

	if (strncmp (cur_tok, "local", sizeof ("local")) == 0 ||
		strncmp (cur_tok, "unix", sizeof ("unix")) == 0) {
		srv->sock.unix_path = strdup (str);
		srv->sock_type = AF_UNIX;

		LIST_INSERT_HEAD (&cf->clamav_servers, srv, next);
		return 1;
	} else if (strncmp (cur_tok, "inet", sizeof ("inet")) == 0) {
		srv->sock.inet.port = htonl (strtol (str, &err_str, 10));
		if (*err_str != '\0') {
			free (srv);
			return 0;
		}

		host_tok = strsep (&cur_tok, "@");
		if (!host_tok || !cur_tok || !inet_aton (cur_tok, &srv->sock.inet.addr)) {
			free (srv);
			return 0;
		}

		srv->sock_type = AF_INET;
		LIST_INSERT_HEAD (&cf->clamav_servers, srv, next);
		return 1;
	}

	return 0;
}

static struct action *
create_action (enum action_type type, const char *message)
{
	struct action *new;

	new = (struct action *)malloc (sizeof (struct action)); 

	if (new == NULL) return NULL;

	new->type = type;
	new->message = strdup (message);

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
		new->args[0].src = strdup (arg1);
		new->args[0].re = pcre_compile (arg1, 0, &read_err, &offset, NULL);
		if (new->args[0].re == NULL) {
			new->args[0].empty = 1;
		}
	}
	if (arg2 == NULL || *arg2 == '\0') {
		new->args[1].empty = 1;
	}
	else {
		new->args[1].src = strdup (arg2);
		new->args[1].re = pcre_compile (arg2, 0, &read_err, &offset, NULL);
		if (new->args[1].re == NULL) {
			new->args[1].empty = 1;
		}
	}

	return new;
}


%}
%union 
{
	char *string;
	struct condition *cond;
	struct action *action;
}

%token	ERROR STRING
%token	ACCEPT REJECTL TEMPFAIL DISCARD QUARANTINE
%token	CONNECT HELO ENVFROM ENVRCPT HEADER MACRO BODY
%token	AND OR NOT
%token  TEMPDIR LOGFILE PIDFILE RULE CLAMAV SPF DCC
%token  FILENAME REGEXP QUOTE SEMICOLON OBRACE EBRACE COMMA EQSIGN
%token  BINDSOCK SOCKCRED
%type	<string>	STRING
%type	<string>	FILENAME
%type	<string>	REGEXP
%type   <string>  	SOCKCRED
%type   <cond>    	expr_l expr term
%type   <action>  		action
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
					syslog (LOG_ERR, "yyparse: malloc: %s", strerror (errno));
				}

				cur_rule->act = $1;
				cur_rule->conditions = cur_conditions;
				LIST_INSERT_HEAD (&cfg->rules, cur_rule, next);
			}
			;

action	: 
	REJECTL STRING		{
		$$ = create_action(ACTION_REJECT, $2);
		if ($$ == NULL) {
			syslog(LOG_ERR, "yyparse: create_action");
			YYERROR;
		}
		free($2);
	}
	| TEMPFAIL STRING	{
		$$ = create_action(ACTION_TEMPFAIL, $2);
		if ($$ == NULL) {
			syslog(LOG_ERR, "yyparse: create_action");
			YYERROR;
		}
		free($2);
	}
	| QUARANTINE STRING	{
		$$ = create_action(ACTION_QUARANTINE, $2);
		if ($$ == NULL) {
			syslog(LOG_ERR, "yyparse: create_action");
			YYERROR;
		}
		free($2);
	}
	| DISCARD 		{
		$$ = create_action(ACTION_DISCARD, "");
		if ($$ == NULL) {
			syslog(LOG_ERR, "yyparse: create_action");
			YYERROR;
		}
	}
	| ACCEPT 		{
		$$ = create_action(ACTION_ACCEPT, "");
		if ($$ == NULL) {
			syslog(LOG_ERR, "yyparse: create_action");
			YYERROR;
		}
	}
	;

expr_l	: 
	expr SEMICOLON		{
		LIST_INIT (cur_conditions);
		$$ = $1;
		if ($$ == NULL) {
			syslog(LOG_ERR, "yyparse: malloc: %s", strerror(errno));
			YYERROR;
		}
		LIST_INSERT_HEAD (cur_conditions, $$, next);
	}
	| expr_l expr	{
		$$ = $2;
		if ($$ == NULL) {
			syslog(LOG_ERR, "yyparse: malloc: %s", strerror(errno));
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
		if ($$ == NULL)
			YYERROR;
		free($2);
		free($3);
	}
	| HELO REGEXP		{
		$$ = create_cond(COND_HELO, $2, NULL);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	| ENVFROM REGEXP	{
		$$ = create_cond(COND_ENVFROM, $2, NULL);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	| ENVRCPT REGEXP	{
		$$ = create_cond(COND_ENVRCPT, $2, NULL);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	| HEADER REGEXP REGEXP	{
		$$ = create_cond(COND_HEADER, $2, $3);
		if ($$ == NULL)
			YYERROR;
		free($2);
		free($3);
	}
	| BODY REGEXP		{
		$$ = create_cond(COND_BODY, $2, NULL);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	;

clamav:
	CLAMAV EQSIGN clamav_params
	;

clamav_params:
	SOCKCRED {
		if (!add_clamav_server (cfg, $1)) {
			yyerror ("yyparse: add_clamav_server");
			YYERROR;
		}
		free ($1);
	}
	| clamav_params COMMA SOCKCRED {
		if (!add_clamav_server (cfg, $3)) {
			yyerror ("yyparse: add_clamav_server");
			YYERROR;
		}
		free ($3);
	}
	;

spf:
	SPF EQSIGN FILENAME {
		if (!read_spf_map (cfg, $3)) {
			yyerror ("yyparse: read_spf_map");
			YYERROR;
		}
		free ($3);
	}
	;

bindsock:
	BINDSOCK EQSIGN SOCKCRED {
		cfg->sock_cred = $3;
	}
	;
%%

