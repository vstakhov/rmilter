/*
 * Copyright (c) 2007-2012, Vsevolod Stakhov
 * All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer. Redistributions in binary form
 * must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with
 * the distribution. Neither the name of the author nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.

 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

%{

#include "pcre.h"
#include "cfg_file.h"

#define YYDEBUG 0

extern struct config_file *cfg;
extern int yylineno;
extern char *yytext;

struct condl *cur_conditions;
struct dkim_domain_entry *cur_domain;
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
	double frac;
}

%token	ERROR STRING QUOTEDSTRING FLAG FLOAT
%token	ACCEPT REJECTL TEMPFAIL DISCARD QUARANTINE
%token	CONNECT HELO ENVFROM ENVRCPT HEADER MACRO BODY
%token	AND OR NOT
%token  TEMPDIR LOGFILE PIDFILE RULE CLAMAV SERVERS ERROR_TIME DEAD_TIME MAXERRORS CONNECT_TIMEOUT PORT_TIMEOUT RESULTS_TIMEOUT SPF DCC
%token  FILENAME REGEXP QUOTE SEMICOLON OBRACE EBRACE COMMA EQSIGN
%token  BINDSOCK SOCKCRED DOMAIN_STR IPADDR IPNETWORK HOSTPORT NUMBER GREYLISTING WHITELIST TIMEOUT EXPIRE EXPIRE_WHITE
%token  MAXSIZE SIZELIMIT SECONDS BUCKET USEDCC MEMCACHED PROTOCOL AWL_ENABLE AWL_POOL AWL_TTL AWL_HITS SERVERS_WHITE SERVERS_LIMITS SERVERS_GREY
%token  LIMITS LIMIT_TO LIMIT_TO_IP LIMIT_TO_IP_FROM LIMIT_WHITELIST LIMIT_WHITELIST_RCPT LIMIT_BOUNCE_ADDRS LIMIT_BOUNCE_TO LIMIT_BOUNCE_TO_IP
%token  SPAMD REJECT_MESSAGE SERVERS_ID ID_PREFIX GREY_PREFIX WHITE_PREFIX RSPAMD_METRIC ALSO_CHECK DIFF_DIR CHECK_SYMBOLS SYMBOLS_DIR
%token  BEANSTALK ID_REGEXP LIFETIME COPY_SERVER GREYLISTED_MESSAGE SPAMD_SOFT_FAIL
%token  SEND_BEANSTALK_COPY SEND_BEANSTALK_HEADERS SEND_BEANSTALK_SPAM SPAM_SERVER STRICT_AUTH
%token	TRACE_SYMBOL TRACE_ADDR WHITELIST_FROM SPAM_HEADER SPAM_HEADER_VALUE SPAMD_GREYLIST EXTENDED_SPAM_HEADERS
%token  DKIM_SECTION DKIM_KEY DKIM_DOMAIN DKIM_SELECTOR DKIM_HEADER_CANON DKIM_BODY_CANON
%token  DKIM_SIGN_ALG DKIM_RELAXED DKIM_SIMPLE DKIM_SHA1 DKIM_SHA256 DKIM_AUTH_ONLY COPY_PROBABILITY
%token  SEND_BEANSTALK_SPAM_EXTRA_DIFF DKIM_FOLD_HEADER SPAMD_RETRY_COUNT SPAMD_RETRY_TIMEOUT SPAMD_TEMPFAIL

%type	<string>	STRING
%type	<string>	QUOTEDSTRING
%type	<string>	FILENAME
%type	<string>	REGEXP
%type   <string>  	SOCKCRED
%type	<string>	IPADDR IPNETWORK
%type	<string>	HOSTPORT
%type 	<string>	ip_net memcached_hosts beanstalk_hosts clamav_addr spamd_addr
%type   <cond>    	expr_l expr term
%type   <action>  	action
%type	<string>	DOMAIN_STR
%type	<limit>		SIZELIMIT
%type	<flag>		FLAG
%type	<bucket>	BUCKET;
%type	<seconds>	SECONDS;
%type	<number>	NUMBER;
%type   <frac>		FLOAT;
%%

file	: /* empty */
	|  file command SEMICOLON { }
	;

command	:
	tempdir
	| strictauth
	| pidfile
	| rule
	| clamav
	| spamd
	| spf
	| bindsock
	| maxsize
	| usedcc
	| memcached
	| beanstalk
	| limits
	| greylisting
	| whitelist
	| dkim
	;

tempdir :
	TEMPDIR EQSIGN FILENAME {
		struct stat st;

		if (stat ($3, &st) == -1) {
			yyerror ("yyparse: cannot stat directory \"%s\": %s", $3, strerror (errno));
			YYERROR;
		}
		if (!S_ISDIR (st.st_mode)) {
			yyerror ("yyparse: \"%s\" is not a directory", $3);
			YYERROR;
		}

		cfg->temp_dir = $3;
	}
	;

pidfile :
	PIDFILE EQSIGN FILENAME {
		cfg->pid_file = $3;
	}
	;

strictauth:
	STRICT_AUTH EQSIGN FLAG {
		cfg->strict_auth = $3;
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
	| expr_l expr SEMICOLON	{
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
	| QUOTEDSTRING {
		$$ = $1;
	}
	| IPADDR{
		$$ = $1;
	}
	| DOMAIN_STR {
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

spamd:
	SPAMD OBRACE spamdbody EBRACE
	;

spamdbody:
	spamdcmd SEMICOLON
	| spamdbody spamdcmd SEMICOLON
	;

spamdcmd:
	spamd_servers
	| spamd_connect_timeout
	| spamd_results_timeout
	| spamd_error_time
	| spamd_dead_time
	| spamd_maxerrors
	| spamd_reject_message
	| spamd_whitelist
	| extra_spamd_servers
	| spamd_rspamd_metric
	| diff_dir
	| symbols_dir
	| check_symbols
	| spamd_soft_fail
	| trace_symbol
	| trace_addr
	| spamd_spam_header
	| spamd_spam_header_value
	| spamd_greylist
	| extended_spam_headers
	| spamd_retry_count
	| spamd_retry_timeout
	| spamd_tempfail
	;

diff_dir :
	DIFF_DIR EQSIGN FILENAME {
		struct stat st;

		if (stat ($3, &st) == -1) {
			yyerror ("yyparse: cannot stat directory \"%s\": %s", $3, strerror (errno));
			YYERROR;
		}
		if (!S_ISDIR (st.st_mode)) {
			yyerror ("yyparse: \"%s\" is not a directory", $3);
			YYERROR;
		}

		cfg->diff_dir = $3;
	}
	;
symbols_dir:
	SYMBOLS_DIR EQSIGN FILENAME {
		struct stat st;

		if (stat ($3, &st) == -1) {
			yyerror ("yyparse: cannot stat directory \"%s\": %s", $3, strerror (errno));
			YYERROR;
		}
		if (!S_ISDIR (st.st_mode)) {
			yyerror ("yyparse: \"%s\" is not a directory", $3);
			YYERROR;
		}

		cfg->symbols_dir = $3;
	}
	;

check_symbols:
	CHECK_SYMBOLS EQSIGN QUOTEDSTRING {
		free (cfg->check_symbols);
		cfg->check_symbols = $3;
	}
	;


spamd_servers:
	SERVERS EQSIGN spamd_server
	;

spamd_server:
	spamd_params
	| spamd_server COMMA spamd_params
	;

spamd_params:
	spamd_addr	{
		if (!add_spamd_server (cfg, $1, 0)) {
			yyerror ("yyparse: add_spamd_server");
			YYERROR;
		}
		free ($1);
	}
	;

extra_spamd_servers:
	ALSO_CHECK EQSIGN extra_spamd_server
	;

extra_spamd_server:
	extra_spamd_params
	| extra_spamd_server COMMA extra_spamd_params
	;

extra_spamd_params:
	spamd_addr	{
		if (!add_spamd_server (cfg, $1, 1)) {
			yyerror ("yyparse: add_spamd_server");
			YYERROR;
		}
		free ($1);
	}
	;

spamd_addr:
	STRING {
		$$ = $1;
	}
	| QUOTEDSTRING {
		$$ = $1;
	}
	| IPADDR{
		$$ = $1;
	}
	| DOMAIN_STR {
		$$ = $1;
	}
	| HOSTPORT {
		$$ = $1;
	}
	| FILENAME {
		$$ = $1;
	}
	;
spamd_error_time:
	ERROR_TIME EQSIGN NUMBER {
		cfg->spamd_error_time = $3;
	}
	;
spamd_dead_time:
	DEAD_TIME EQSIGN NUMBER {
		cfg->spamd_dead_time = $3;
	}
	;
spamd_maxerrors:
	MAXERRORS EQSIGN NUMBER {
		cfg->spamd_maxerrors = $3;
	}
	;
spamd_connect_timeout:
	CONNECT_TIMEOUT EQSIGN SECONDS {
		cfg->spamd_connect_timeout = $3;
	}
	;
spamd_results_timeout:
	RESULTS_TIMEOUT EQSIGN SECONDS {
		cfg->spamd_results_timeout = $3;
	}
	;
spamd_reject_message:
	REJECT_MESSAGE EQSIGN QUOTEDSTRING {
		free (cfg->spamd_reject_message);
		cfg->spamd_reject_message = $3;
	}
	;
spamd_whitelist:
	WHITELIST EQSIGN spamd_ip_list
	;

spamd_ip_list:
	spamd_ip
	| spamd_ip_list COMMA spamd_ip
	;

spamd_ip:
	ip_net {
		if (add_ip_radix (cfg->spamd_whitelist, $1) == 0) {
			YYERROR;
		}
	}
	;

spamd_rspamd_metric:
	RSPAMD_METRIC EQSIGN QUOTEDSTRING {
		free (cfg->rspamd_metric);
		cfg->rspamd_metric = $3;
	}
	;

spamd_soft_fail:
	SPAMD_SOFT_FAIL EQSIGN FLAG {
		if ($3) {
			cfg->spamd_soft_fail = 1;
		}
	}
	;

extended_spam_headers:
	EXTENDED_SPAM_HEADERS EQSIGN FLAG {
		if ($3) {
			cfg->extended_spam_headers = 1;
		}
	}
	;

spamd_greylist:
	SPAMD_GREYLIST EQSIGN FLAG {
		if ($3) {
			cfg->spamd_greylist = 1;
		}
	}
	;

spamd_spam_header:
	SPAM_HEADER EQSIGN QUOTEDSTRING {
		free (cfg->spam_header);
		cfg->spam_header = $3;
	}
	;

spamd_spam_header_value:
	SPAM_HEADER_VALUE EQSIGN QUOTEDSTRING {
		free (cfg->spam_header_value);
		cfg->spam_header_value = $3;
	}
	;

trace_symbol:
	TRACE_SYMBOL EQSIGN QUOTEDSTRING {
		free (cfg->trace_symbol);
		cfg->trace_symbol = $3;
	}
	;

trace_addr:
	TRACE_ADDR EQSIGN QUOTEDSTRING {
		free (cfg->trace_addr);
		cfg->trace_addr = $3;
	}
	;
spamd_retry_timeout:
	SPAMD_RETRY_TIMEOUT EQSIGN SECONDS {
		cfg->spamd_retry_timeout = $3;
	}
	;
spamd_retry_count:
	SPAMD_RETRY_COUNT EQSIGN NUMBER {
		cfg->spamd_retry_count = $3;
	}
	;
spamd_tempfail:
	SPAMD_TEMPFAIL EQSIGN FLAG {
		cfg->spamd_temp_fail = $3;
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
	DOMAIN_STR {
		if (!add_spf_domain (cfg, $1)) {
			yyerror ("yyparse: add_spf_domain");
			YYERROR;
		}
	}
	| STRING {
		if (!add_spf_domain (cfg, $1)) {
			yyerror ("yyparse: add_spf_domain");
			YYERROR;
		}
	}
	| QUOTEDSTRING {
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
	| BINDSOCK EQSIGN QUOTEDSTRING {
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
	| greylisting_whitelist_expire
	| greylisted_message
	| awl_enable
	| awl_hits
	| awl_pool
	| awl_ttl
	;

greylisting_timeout:
	TIMEOUT EQSIGN SECONDS {
		/* This value is in seconds, not in milliseconds */
		cfg->greylisting_timeout = $3 / 1000;
	}
	;

greylisting_expire:
	EXPIRE EQSIGN SECONDS {
		/* This value is in seconds, not in milliseconds */
		cfg->greylisting_expire = $3 / 1000;
	}
	;

greylisting_whitelist_expire:
	EXPIRE_WHITE EQSIGN SECONDS {
		/* This value is in seconds, not in milliseconds */
		cfg->whitelisting_expire = $3 / 1000;
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
		if (add_ip_radix (cfg->grey_whitelist_tree, $1) == 0) {
			YYERROR;
		}
	}
	;

awl_enable:
	AWL_ENABLE EQSIGN FLAG {
		if ($3 == -1) {
			yyerror ("yyparse: cannot parse flag");
			YYERROR;
		}
		cfg->awl_enable = $3;
	}
	;
awl_hits:
	AWL_HITS EQSIGN NUMBER {
		cfg->awl_max_hits = $3;
	}
	;

awl_pool:
	AWL_POOL EQSIGN SIZELIMIT {
		cfg->awl_pool_size = $3;
	}
	;

awl_ttl:
	AWL_TTL EQSIGN SECONDS {
		/* Time is in seconds */
		cfg->awl_ttl = $3 / 1000;
	}
	;

greylisted_message:
	GREYLISTED_MESSAGE EQSIGN QUOTEDSTRING {
		free (cfg->greylisted_message);
		cfg->greylisted_message = $3;
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
	memcached_grey_servers
	| memcached_white_servers
	| memcached_limits_servers
	| memcached_id_servers
	| memcached_connect_timeout
	| memcached_error_time
	| memcached_dead_time
	| memcached_maxerrors
	| memcached_protocol
	| memcached_id_prefix
	| memcached_grey_prefix
	| memcached_white_prefix
	;

memcached_grey_servers:
	SERVERS_GREY EQSIGN memcached_grey_server
	;

memcached_grey_server:
	memcached_grey_params
	| memcached_grey_server COMMA memcached_grey_params
	;

memcached_grey_params:
	OBRACE memcached_hosts COMMA memcached_hosts EBRACE {
		if (!add_memcached_server (cfg, $2, $4, MEMCACHED_SERVER_GREY)) {
			yyerror ("yyparse: add_memcached_server");
			YYERROR;
		}
		free ($2);
		free ($4);
	}
	| memcached_hosts {
		if (!add_memcached_server (cfg, $1, NULL, MEMCACHED_SERVER_GREY)) {
			yyerror ("yyparse: add_memcached_server");
			YYERROR;
		}
		free ($1);
	}
	;

memcached_white_servers:
	SERVERS_WHITE EQSIGN memcached_white_server
	;

memcached_white_server:
	memcached_white_params
	| memcached_white_server COMMA memcached_white_params
	;

memcached_white_params:
	OBRACE memcached_hosts COMMA memcached_hosts EBRACE {
		if (!add_memcached_server (cfg, $2, $4, MEMCACHED_SERVER_WHITE)) {
			yyerror ("yyparse: add_memcached_server");
			YYERROR;
		}
		free ($2);
		free ($4);
	}
	| memcached_hosts {
		if (!add_memcached_server (cfg, $1, NULL, MEMCACHED_SERVER_WHITE)) {
			yyerror ("yyparse: add_memcached_server");
			YYERROR;
		}
		free ($1);
	}
	;

memcached_limits_servers:
	SERVERS_LIMITS EQSIGN memcached_limits_server
	;

memcached_limits_server:
	memcached_limits_params
	| memcached_limits_server COMMA memcached_limits_params
	;

memcached_limits_params:
	memcached_hosts {
		if (!add_memcached_server (cfg, $1, NULL, MEMCACHED_SERVER_LIMITS)) {
			yyerror ("yyparse: add_memcached_server");
			YYERROR;
		}
		free ($1);
	}
	;

memcached_id_servers:
	SERVERS_ID EQSIGN memcached_id_server
	;

memcached_id_server:
	memcached_id_params
	| memcached_id_server COMMA memcached_id_params
	;

memcached_id_params:
	memcached_hosts {
		if (!add_memcached_server (cfg, $1, NULL, MEMCACHED_SERVER_ID)) {
			yyerror ("yyparse: add_memcached_server");
			YYERROR;
		}
		free ($1);
	}
	;

memcached_hosts:
	STRING
	| QUOTEDSTRING
	| IPADDR
	| DOMAIN_STR
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
memcached_id_prefix:
	ID_PREFIX EQSIGN QUOTEDSTRING {
		free (cfg->id_prefix);
		cfg->id_prefix = $3;
	}
	;

memcached_grey_prefix:
	GREY_PREFIX EQSIGN QUOTEDSTRING {
		free (cfg->grey_prefix);
		cfg->grey_prefix = $3;
	}
	;

memcached_white_prefix:
	WHITE_PREFIX EQSIGN QUOTEDSTRING {
		free (cfg->white_prefix);
		cfg->white_prefix = $3;
	}
	;

beanstalk:
	BEANSTALK OBRACE beanstalkbody EBRACE
	;

beanstalkbody:
	beanstalkcmd SEMICOLON
	| beanstalkbody beanstalkcmd SEMICOLON
	;

beanstalkcmd:
	beanstalk_servers
	| beanstalk_copy_server
	| beanstalk_spam_server
	| beanstalk_connect_timeout
	| beanstalk_error_time
	| beanstalk_dead_time
	| beanstalk_maxerrors
	| beanstalk_protocol
	| beanstalk_id_regexp
	| beanstalk_lifetime
	| send_beanstalk_headers
	| send_beanstalk_spam
	| send_beanstalk_copy
	| beanstalk_copy_prob
	| beanstalk_extra_diff
	;

beanstalk_servers:
	SERVERS EQSIGN beanstalk_server
	;

beanstalk_server:
	beanstalk_params
	| beanstalk_server COMMA beanstalk_params
	;

beanstalk_params:
	beanstalk_hosts {
		if (!add_beanstalk_server (cfg, $1, 0)) {
			yyerror ("yyparse: add_beanstalk_server");
			YYERROR;
		}
		free ($1);
	}
	;

beanstalk_copy_server:
	COPY_SERVER EQSIGN beanstalk_hosts {
		if (!add_beanstalk_server (cfg, $3, 1)) {
			yyerror ("yyparse: add_beanstalk_server");
			YYERROR;
		}
		free ($3);
	}
	;
beanstalk_spam_server:
	SPAM_SERVER EQSIGN beanstalk_hosts {
		if (!add_beanstalk_server (cfg, $3, 2)) {
			yyerror ("yyparse: add_beanstalk_server");
			YYERROR;
		}
		free ($3);
	}
	;

beanstalk_hosts:
	STRING
	| QUOTEDSTRING
	| IPADDR
	| DOMAIN_STR
	| HOSTPORT
	;

beanstalk_error_time:
	ERROR_TIME EQSIGN NUMBER {
		cfg->beanstalk_error_time = $3;
	}
	;
beanstalk_dead_time:
	DEAD_TIME EQSIGN NUMBER {
		cfg->beanstalk_dead_time = $3;
	}
	;
beanstalk_maxerrors:
	MAXERRORS EQSIGN NUMBER {
		cfg->beanstalk_maxerrors = $3;
	}
	;
beanstalk_connect_timeout:
	CONNECT_TIMEOUT EQSIGN SECONDS {
		cfg->beanstalk_connect_timeout = $3;
	}
	;

beanstalk_protocol:
	PROTOCOL EQSIGN STRING {
		if (strncasecmp ($3, "udp", sizeof ("udp") - 1) == 0) {
			cfg->beanstalk_protocol = BEANSTALK_UDP_TEXT;
		}
		else if (strncasecmp ($3, "tcp", sizeof ("tcp") - 1) == 0) {
			cfg->beanstalk_protocol = BEANSTALK_TCP_TEXT;
		}
		else {
			yyerror ("yyparse: cannot recognize protocol: %s", $3);
			YYERROR;
		}
	}
	;
beanstalk_id_regexp:
	ID_REGEXP EQSIGN QUOTEDSTRING {
		int offset;
		const char *read_err;

		if (cfg->special_mid_re) {
			pcre_free (cfg->special_mid_re);
		}
		cfg->special_mid_re = pcre_compile ($3, 0, &read_err, &offset, NULL);
		if (cfg->special_mid_re == NULL) {
			yyerror ("yyparse: pcre_compile failed: %s", read_err);
			YYERROR;
		}

		free($3);
	}
	;
beanstalk_lifetime:
	LIFETIME EQSIGN NUMBER {
		cfg->beanstalk_lifetime = $3;
	}
	;

send_beanstalk_headers:
	SEND_BEANSTALK_HEADERS EQSIGN FLAG {
		if ($3) {
			cfg->send_beanstalk_headers = 1;
		}
		else {
			cfg->send_beanstalk_headers = 0;
		}
	}
	;
send_beanstalk_copy:
	SEND_BEANSTALK_COPY EQSIGN FLAG {
		if ($3) {
			cfg->send_beanstalk_copy = 1;
		}
		else {
			cfg->send_beanstalk_copy = 0;
		}
	}
	;
send_beanstalk_spam:
	SEND_BEANSTALK_SPAM EQSIGN FLAG {
		if ($3) {
			cfg->send_beanstalk_spam = 1;
		}
		else {
			cfg->send_beanstalk_spam = 0;
		}
	}
	;

beanstalk_copy_prob:
	COPY_PROBABILITY EQSIGN NUMBER {
		cfg->beanstalk_copy_prob = $3;
	}
	| COPY_PROBABILITY EQSIGN FLOAT {
		cfg->beanstalk_copy_prob = $3;
	}
	;

beanstalk_extra_diff:
	SEND_BEANSTALK_SPAM_EXTRA_DIFF EQSIGN FLAG {
		if ($3) {
			cfg->send_beanstalk_extra_diff = 1;
		}
		else {
			cfg->send_beanstalk_extra_diff = 0;
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
	| limit_whitelist
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
limit_whitelist:
	LIMIT_WHITELIST EQSIGN whitelist_ip_list
	;
whitelist_ip_list:
	ip_net {
		if (add_ip_radix (cfg->limit_whitelist_tree, $1) == 0) {
			YYERROR;
		}
	}
	| whitelist_ip_list COMMA ip_net {
		if (add_ip_radix (cfg->limit_whitelist_tree, $3) == 0) {
			YYERROR;
		}
	}
	;

limit_whitelist_rcpt:
	LIMIT_WHITELIST_RCPT EQSIGN whitelist_rcpt_list
	;
whitelist_rcpt_list:
	STRING {
		add_rcpt_whitelist (cfg, $1, 0);
	}
	| QUOTEDSTRING {
		add_rcpt_whitelist (cfg, $1, 0);
	}
	| whitelist_rcpt_list COMMA STRING {
		add_rcpt_whitelist (cfg, $3, 0);
	}
	| whitelist_rcpt_list COMMA QUOTEDSTRING {
		add_rcpt_whitelist (cfg, $3, 0);
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
	| QUOTEDSTRING {
		struct addr_list_entry *t;
		t = (struct addr_list_entry *)malloc (sizeof (struct addr_list_entry));
		t->addr = strdup ($1);
		t->len = strlen (t->addr);
		LIST_INSERT_HEAD (&cfg->bounce_addrs, t, next);
	}
	| bounce_addr_list COMMA QUOTEDSTRING {
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


whitelist:
	WHITELIST EQSIGN whitelist_list
	;
whitelist_list:
	STRING {
		add_rcpt_whitelist (cfg, $1, 1);
	}
	| whitelist_list COMMA STRING {
		add_rcpt_whitelist (cfg, $3, 1);
	}
	| QUOTEDSTRING {
		add_rcpt_whitelist (cfg, $1, 1);
	}
	| whitelist_list COMMA QUOTEDSTRING {
		add_rcpt_whitelist (cfg, $3, 1);
	}
	;


dkim:
	DKIM_SECTION OBRACE dkimbody EBRACE
	;

dkimbody:
	dkimcmd SEMICOLON
	| dkimbody dkimcmd SEMICOLON
	;

dkimcmd:
	dkim_key
	| dkim_domain
	| dkim_header_canon
	| dkim_body_canon
	| dkim_sign_alg
	| dkim_auth_only
	| dkim_fold_header
	;

dkim_domain:
	DKIM_DOMAIN OBRACE dkim_domain_body EBRACE {
		if (cur_domain == NULL || cur_domain->domain == NULL || cur_domain->selector == NULL) {
			yyerror ("yyparse: incomplete dkim definition");
			YYERROR;
		}
		if (!cur_domain->is_loaded) {
			/* Assume it as wildcard domain */
			cur_domain->is_wildcard = 1;
		}
		HASH_ADD_KEYPTR (hh, cfg->dkim_domains, cur_domain->domain, strlen (cur_domain->domain), cur_domain);
		cur_domain = NULL;
	}
	;

dkim_domain_body:
	dkim_domain_cmd SEMICOLON
	| dkim_domain_body dkim_domain_cmd SEMICOLON
	;

dkim_domain_cmd:
	dkim_key
	| dkim_domain
	| dkim_selector
	;

dkim_key:
	DKIM_KEY EQSIGN FILENAME {
		struct stat st;
		int fd;
		if (cur_domain == NULL) {
			cur_domain = malloc (sizeof (struct dkim_domain_entry));
			memset (cur_domain, 0, sizeof (struct dkim_domain_entry));
		}
		if (stat ($3, &st) != -1 && S_ISREG (st.st_mode)) {
			cur_domain->keylen = st.st_size;
			if ((fd = open ($3, O_RDONLY)) != -1) {
				if ((cur_domain->key = mmap (NULL, cur_domain->keylen, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
					yyerror ("yyparse: cannot mmap: %s, %s", $3, strerror (errno));
					close (fd);
					YYERROR;
				}
				else {
					cur_domain->is_loaded = 1;
				}
				close (fd);
			}
		}
		cur_domain->keyfile = strdup ($3);
	}
	;

dkim_domain:
	DKIM_DOMAIN EQSIGN QUOTEDSTRING {

		if (cur_domain == NULL) {
			cur_domain = malloc (sizeof (struct dkim_domain_entry));
			memset (cur_domain, 0, sizeof (struct dkim_domain_entry));
		}
		else {
			free (cur_domain->domain);
		}

		cur_domain->domain = $3;
	}
	;

dkim_selector:
	DKIM_SELECTOR EQSIGN QUOTEDSTRING {

		if (cur_domain == NULL) {
			cur_domain = malloc (sizeof (struct dkim_domain_entry));
			memset (cur_domain, 0, sizeof (struct dkim_domain_entry));
		}
		else {
			free (cur_domain->selector);
		}
		cur_domain->selector = $3;
		free ($3);
	}
	;

dkim_header_canon:
	DKIM_HEADER_CANON EQSIGN DKIM_SIMPLE {
		cfg->dkim_relaxed_header = 0;
	}
	| DKIM_HEADER_CANON EQSIGN DKIM_RELAXED {
		cfg->dkim_relaxed_header = 1;
	}
	;

dkim_body_canon:
	DKIM_BODY_CANON EQSIGN DKIM_SIMPLE {
		cfg->dkim_relaxed_body = 0;
	}
	| DKIM_BODY_CANON EQSIGN DKIM_RELAXED {
		cfg->dkim_relaxed_body = 1;
	}
	;

dkim_sign_alg:
	DKIM_SIGN_ALG EQSIGN DKIM_SHA1 {
		cfg->dkim_sign_sha256 = 0;
	}
	| DKIM_SIGN_ALG EQSIGN DKIM_SHA256 {
		cfg->dkim_sign_sha256 = 1;
	}
	;

dkim_auth_only:
	DKIM_AUTH_ONLY EQSIGN FLAG {
		if ($3) {
			cfg->dkim_auth_only = 1;
		}
		else {
			cfg->dkim_auth_only = 0;
		}
	}
	;

dkim_fold_header:
	DKIM_FOLD_HEADER EQSIGN FLAG {
		if ($3) {
			cfg->dkim_fold_header = 1;
		}
		else {
			cfg->dkim_fold_header = 0;
		}
	}
	;

%%
/*
 * vi:ts=4
 */
