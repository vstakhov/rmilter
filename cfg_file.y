/* $Id$ */

%{

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pcre.h"
#include "cfg_file.h"

#define YYDEBUG 0

extern struct config_file *cfg;
extern int yylineno;
extern char *yytext;

struct condl *cur_conditions;
uint8_t cur_flags = 0;

%}
%union 
{
	char *string;
	struct condition *cond;
	struct action *action;
	size_t limit;
	bucket_t bucket;
	char flag;
	unsigned int seconds;
	unsigned int number;
}

%token	ERROR STRING QUOTEDSTRING FLAG
%token	ACCEPT REJECTL TEMPFAIL DISCARD QUARANTINE
%token	CONNECT HELO ENVFROM ENVRCPT HEADER MACRO BODY
%token	AND OR NOT
%token  TEMPDIR LOGFILE PIDFILE RULE CLAMAV SERVERS ERROR_TIME DEAD_TIME MAXERRORS CONNECT_TIMEOUT PORT_TIMEOUT RESULTS_TIMEOUT SPF DCC
%token  FILENAME REGEXP QUOTE SEMICOLON OBRACE EBRACE COMMA EQSIGN
%token  BINDSOCK SOCKCRED DOMAIN IPADDR IPNETWORK HOSTPORT NUMBER GREYLISTING WHITELIST TIMEOUT EXPIRE
%token  MAXSIZE SIZELIMIT SECONDS BUCKET USEDCC MEMCACHED PROTOCOL
%token  LIMITS LIMIT_TO LIMIT_TO_IP LIMIT_TO_IP_FROM LIMIT_WHITELIST_IP LIMIT_WHITELIST_RCPT LIMIT_BOUNCE_ADDRS LIMIT_BOUNCE_TO LIMIT_BOUNCE_TO_IP

%type	<string>	STRING
%type	<string>	QUOTEDSTRING
%type	<string>	FILENAME
%type	<string>	REGEXP
%type   <string>  	SOCKCRED
%type	<string>	IPADDR IPNETWORK
%type	<string>	HOSTPORT
%type 	<string>	ip_net memcached_hosts clamav_addr
%type   <cond>    	expr_l expr term
%type   <action>  	action
%type	<string>	DOMAIN
%type	<limit>		SIZELIMIT
%type	<flag>		FLAG
%type	<bucket>	BUCKET;
%type	<seconds>	SECONDS;
%type	<number>	NUMBER;
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
	| limits
	| greylisting
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
	CLAMAV OBRACE clamavbody EBRACE
	;

clamavbody:
	clamavcmd SEMICOLON
	| clamavbody clamavcmd SEMICOLON
	;

clamavcmd:
	clamav_servers
	| clamav_connect_timeout
	| clamav_port_timeout
	| clamav_results_timeout
	| clamav_error_time
	| clamav_dead_time
	| clamav_maxerrors
	;

clamav_servers:
	SERVERS EQSIGN clamav_server
	;

clamav_server:
	clamav_params
	| clamav_server COMMA clamav_params
	;

clamav_params:
	clamav_addr	{
		if (!add_clamav_server (cfg, $1)) {
			yyerror ("yyparse: add_clamav_server");
			YYERROR;
		}
		free ($1);
	}
	;
clamav_addr:
	STRING {
		$$ = $1;
	}
	| IPADDR{
		$$ = $1;
	}
	| DOMAIN {
		$$ = $1;
	}
	| HOSTPORT {
		$$ = $1;
	}
	| FILENAME {
		$$ = $1;
	}
	;
clamav_error_time:
	ERROR_TIME EQSIGN NUMBER {
		cfg->clamav_error_time = $3;
	}
	;
clamav_dead_time:
	DEAD_TIME EQSIGN NUMBER {
		cfg->clamav_dead_time = $3;
	}
	;
clamav_maxerrors:
	MAXERRORS EQSIGN NUMBER {
		cfg->clamav_maxerrors = $3;
	}
	;
clamav_connect_timeout:
	CONNECT_TIMEOUT EQSIGN SECONDS {
		cfg->clamav_connect_timeout = $3;
	}
	;
clamav_port_timeout:
	PORT_TIMEOUT EQSIGN SECONDS {
		cfg->clamav_port_timeout = $3;
	}
	;
clamav_results_timeout:
	RESULTS_TIMEOUT EQSIGN SECONDS {
		cfg->clamav_results_timeout = $3;
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
	MAXSIZE EQSIGN SIZELIMIT {
		cfg->sizelimit = $3;
	}
	| MAXSIZE EQSIGN NUMBER {
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
	;

greylisting:
	GREYLISTING OBRACE greylistingbody EBRACE
	;

greylistingbody:
	greylistingcmd SEMICOLON
	| greylistingbody greylistingcmd SEMICOLON
	;

greylistingcmd:
	greylisting_whitelist
	| greylisting_timeout
	| greylisting_expire
	;

greylisting_timeout:
	TIMEOUT EQSIGN SECONDS {
		cfg->greylisting_timeout = $3;
	}
	;

greylisting_expire:
	EXPIRE EQSIGN SECONDS {
		cfg->greylisting_expire = $3;
	}
	;

greylisting_whitelist:
	WHITELIST EQSIGN greylisting_ip_list
	;

greylisting_ip_list:
	greylisting_ip
	| greylisting_ip_list COMMA greylisting_ip
	;

greylisting_ip:
	ip_net {
		if (add_ip_radix (cfg, $1) == 0) {
			YYERROR;
		}
	}
	;

ip_net:
	IPADDR
	| IPNETWORK
	;

memcached:
	MEMCACHED OBRACE memcachedbody EBRACE
	;

memcachedbody:
	memcachedcmd SEMICOLON
	| memcachedbody memcachedcmd SEMICOLON
	;

memcachedcmd:
	memcached_servers
	| memcached_connect_timeout
	| memcached_error_time
	| memcached_dead_time
	| memcached_maxerrors
	| memcached_protocol
	;

memcached_servers:
	SERVERS EQSIGN memcached_server
	;

memcached_server:
	memcached_params
	| memcached_server COMMA memcached_params
	;

memcached_params:
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
	| IPADDR
	| DOMAIN
	| HOSTPORT
	;
memcached_error_time:
	ERROR_TIME EQSIGN NUMBER {
		cfg->memcached_error_time = $3;
	}
	;
memcached_dead_time:
	DEAD_TIME EQSIGN NUMBER {
		cfg->memcached_dead_time = $3;
	}
	;
memcached_maxerrors:
	MAXERRORS EQSIGN NUMBER {
		cfg->memcached_maxerrors = $3;
	}
	;
memcached_connect_timeout:
	CONNECT_TIMEOUT EQSIGN SECONDS {
		cfg->memcached_connect_timeout = $3;
	}
	;

memcached_protocol:
	PROTOCOL EQSIGN STRING {
		if (strncasecmp ($3, "udp", sizeof ("udp") - 1) == 0) {
			cfg->memcached_protocol = UDP_TEXT;
		}
		else if (strncasecmp ($3, "tcp", sizeof ("tcp") - 1) == 0) {
			cfg->memcached_protocol = TCP_TEXT;
		}
		else {
			yyerror ("yyparse: cannot recognize protocol: %s", $3);
			YYERROR;
		}
	}
	;

limits:
	LIMITS OBRACE limitsbody EBRACE
	;

limitsbody:
	limitcmd SEMICOLON
	| limitsbody limitcmd SEMICOLON
	;
limitcmd:
	limit_to
	| limit_to_ip
	| limit_to_ip_from
	| limit_whitelist_ip
	| limit_whitelist_rcpt
	| limit_bounce_addrs
	| limit_bounce_to
	| limit_bounce_to_ip
	;

limit_to:
	LIMIT_TO EQSIGN BUCKET {
		cfg->limit_to.burst = $3.burst;
		cfg->limit_to.rate = $3.rate;
	}
	;
limit_to_ip:
	LIMIT_TO_IP EQSIGN BUCKET {
		cfg->limit_to_ip.burst = $3.burst;
		cfg->limit_to_ip.rate = $3.rate;
	}
	;
limit_to_ip_from:
	LIMIT_TO_IP_FROM EQSIGN BUCKET {
		cfg->limit_to_ip_from.burst = $3.burst;
		cfg->limit_to_ip_from.rate = $3.rate;
	}
	;
limit_whitelist_ip:
	LIMIT_WHITELIST_IP EQSIGN whitelist_ip_list
	;
whitelist_ip_list:
	IPADDR {
		struct ip_list_entry *t;
		t = (struct ip_list_entry *)malloc (sizeof (struct ip_list_entry));
		if (inet_aton ($1, &t->addr) == 0) {
			yyerror ("yyparse: invalid ip address: %s", $1);
			YYERROR;
		}
		LIST_INSERT_HEAD (&cfg->whitelist_ip, t, next);
	}
	| whitelist_ip_list COMMA IPADDR {
		struct ip_list_entry *t;
		t = (struct ip_list_entry *)malloc (sizeof (struct ip_list_entry));
		if (inet_aton ($3, &t->addr) == 0) {
			yyerror ("yyparse: invalid ip address: %s", $3);
			YYERROR;
		}
		LIST_INSERT_HEAD (&cfg->whitelist_ip, t, next);
	}
	;
	
limit_whitelist_rcpt:
	LIMIT_WHITELIST_RCPT EQSIGN whitelist_rcpt_list
	;
whitelist_rcpt_list:
	STRING {
		struct addr_list_entry *t;
		t = (struct addr_list_entry *)malloc (sizeof (struct addr_list_entry));
		t->addr = strdup ($1);
		t->len = strlen (t->addr);
		LIST_INSERT_HEAD (&cfg->whitelist_rcpt, t, next);
	}
	| whitelist_rcpt_list COMMA STRING {
		struct addr_list_entry *t;
		t = (struct addr_list_entry *)malloc (sizeof (struct addr_list_entry));
		t->addr = strdup ($3);
		t->len = strlen (t->addr);
		LIST_INSERT_HEAD (&cfg->whitelist_rcpt, t, next);
	}
	;

limit_bounce_addrs:
	LIMIT_BOUNCE_ADDRS EQSIGN bounce_addr_list
	;
bounce_addr_list:
	STRING {
		struct addr_list_entry *t;
		t = (struct addr_list_entry *)malloc (sizeof (struct addr_list_entry));
		t->addr = strdup ($1);
		t->len = strlen (t->addr);
		LIST_INSERT_HEAD (&cfg->bounce_addrs, t, next);
	}
	| bounce_addr_list COMMA STRING {
		struct addr_list_entry *t;
		t = (struct addr_list_entry *)malloc (sizeof (struct addr_list_entry));
		t->addr = strdup ($3);
		t->len = strlen (t->addr);
		LIST_INSERT_HEAD (&cfg->bounce_addrs, t, next);
	}
	;


limit_bounce_to:
	LIMIT_BOUNCE_TO EQSIGN BUCKET {
		cfg->limit_bounce_to.burst = $3.burst;
		cfg->limit_bounce_to.rate = $3.rate;
	}
	;

limit_bounce_to_ip:
	LIMIT_BOUNCE_TO_IP EQSIGN BUCKET {
		cfg->limit_bounce_to_ip.burst = $3.burst;
		cfg->limit_bounce_to_ip.rate = $3.rate;
	}
	;
%%
/* 
 * vi:ts=4 
 */
