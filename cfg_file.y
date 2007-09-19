/* $Id$ */

%{

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libmilter/mfapi.h>
#include <queue.h>

#include "cfg_file.h"

#define YYSTYPE char *

int		 yyerror(char *, ...);
int		 yyparse(void);

static char		*err_str = NULL;
static size_t		 err_len = 0;
static const char	*infile = NULL;
static FILE		*fin = NULL;
static int		 errors = 0;

extern struct config_file *cfg;

%}

%union {
	char *string;
	struct condition *cond;
	struct action *action;
}

%token	ERROR STRING
%token	ACCEPT REJECT TEMPFAIL DISCARD QUARANTINE
%token	CONNECT HELO ENVFROM ENVRCPT HEADER MACRO BODY
%token	AND OR NOT
%token  LOGFILE PIDFILE RULE CLAMAV SPF DCC
%token  FILENAME REGEXP QUOTE SEMICOLON OBRACE EBRACE COMMA EQSIGN
%token  BINDSOCK UNIXSOCK TCPSOCK
%type	<string>	STRING
%type	<string>	FILENAME
%type	<string>	REGEXP
%type   <string>  	UNIXSOCK TCPSOCK
%type   <cond>    	expr_l expr term
%type   <action>  	action
%%

file	: /* empty */
	|  file command SEMICOLON		{ }
	;

command	: 
	logfile SEMICOLON
	| pidfile SEMICOLON
	| rule SEMICOLON
	| clamav SEMICOLON
	| spf SEMICOLON
	| bindsock SEMICOLON
	;

logfile :
	LOGFILE EQSIGN FILENAME {
		cfg->log_file = $3;
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
			}
			;

action	: 
	REJECT STRING		{
		$$ = create_action(cfg, ACTION_REJECT, $2);
		if ($$ == NULL) {
			yyerror("yyparse: create_action");
			YYERROR;
		}
		free($2);
	}
	| TEMPFAIL STRING	{
		$$ = create_action(cfg, ACTION_TEMPFAIL, $2);
		if ($$ == NULL) {
			yyerror("yyparse: create_action");
			YYERROR;
		}
		free($2);
	}
	| QUARANTINE STRING	{
		$$ = create_action(cfg, ACTION_QUARANTINE, $2);
		if ($$ == NULL) {
			yyerror("yyparse: create_action");
			YYERROR;
		}
		free($2);
	}
	| DISCARD 		{
		$$ = create_action(cfg, ACTION_DISCARD, "");
		if ($$ == NULL) {
			yyerror("yyparse: create_action");
			YYERROR;
		}
	}
	| ACCEPT 		{
		$$ = create_action(cfg, ACTION_ACCEPT, "");
		if ($$ == NULL) {
			yyerror("yyparse: create_action");
			YYERROR;
		}
	}
	;

expr_l	: 
	expr SEMICOLON		{
		$$ = calloc(1, sizeof(struct expr_list));
		if ($$ == NULL) {
			yyerror("yyparse: calloc: %s", strerror(errno));
			YYERROR;
		}
		$$->expr = $1;
	}
	| expr_l expr	{
		$$ = calloc(1, sizeof(struct expr_list));
		if ($$ == NULL) {
			yyerror("yyparse: calloc: %s", strerror(errno));
			YYERROR;
		}
		$$->expr = $2;
		$$->next = $1;
	}
	;

expr	: 
	term			{
		$$ = $1;
	}
	| NOT term		{
		$$ = create_expr(cfg, EXPR_NOT, $2, NULL);
		if ($$ == NULL) {
			yyerror("yyparse: create_expr");
			YYERROR;
		}
	}
	;

term	: 
	CONNECT REGEXP REGEXP	{
		$$ = create_cond(cfg, COND_CONNECT, $2, $3);
		if ($$ == NULL)
			YYERROR;
		free($2);
		free($3);
	}
	| HELO REGEXP		{
		$$ = create_cond(cfg, COND_HELO, $2, NULL);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	| ENVFROM REGEXP	{
		$$ = create_cond(cfg, COND_ENVFROM, $2, NULL);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	| ENVRCPT REGEXP	{
		$$ = create_cond(cfg, COND_ENVRCPT, $2, NULL);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	| HEADER REGEXP REGEXP	{
		$$ = create_cond(cfg, COND_HEADER, $2, $3);
		if ($$ == NULL)
			YYERROR;
		free($2);
		free($3);
	}
	| BODY REGEXP		{
		$$ = create_cond(cfg, COND_BODY, $2, NULL);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	;

clamav:
	CLAMAV EQSIGN clamav_params
	;

clamav_params:
	STRING {
		if (!add_clamav_server (cfg, $1))
			YYERROR;
		free ($1);
	}
	| clamav_params COMMA STRING {
		if (!add_clamav_server (cfg, $3))
			YYERROR;
		free ($3);
	}
	;

spf:
	SPF EQSIGN FILENAME {
		if (!read_spf_map (cfg, $3))
			YYERROR;
		free ($3);
	}
	;

bindsock:
	BINDSOCK EQSIGN UNIXSOCK {
		cfg->sock_cred = $3;
	}
	| BINDSOCK EQSIGN TCPSOCK {
		cfg->sock_cred = $3;
	}
	;
%%

