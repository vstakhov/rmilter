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

#include "cfg_file.h"

#define YYDEBUG 1

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
	size_t limit;
	bucket_t bucket;
	char flag;
	unsigned int seconds;
	unsigned int number;
	double frac;
}

%token	ERROR STRING QUOTEDSTRING FLAG FLOAT
%token  TEMPDIR LOGFILE PIDFILE CLAMAV SERVERS ERROR_TIME DEAD_TIME MAXERRORS CONNECT_TIMEOUT PORT_TIMEOUT RESULTS_TIMEOUT SPF DCC
%token  FILENAME REGEXP QUOTE SEMICOLON OBRACE EBRACE COMMA EQSIGN
%token  BINDSOCK SOCKCRED DOMAIN_STR IPADDR IPNETWORK HOSTPORT NUMBER GREYLISTING WHITELIST TIMEOUT EXPIRE EXPIRE_WHITE SYSLOGNAME
%token  MAXSIZE SIZELIMIT SECONDS BUCKET USEDCC MEMCACHED PROTOCOL SERVERS_WHITE SERVERS_LIMITS SERVERS_GREY SERVERS_COPY SERVERS_SPAM
%token  LIMITS LIMIT_TO LIMIT_TO_IP LIMIT_TO_IP_FROM LIMIT_WHITELIST LIMIT_WHITELIST_RCPT LIMIT_BOUNCE_ADDRS LIMIT_BOUNCE_TO LIMIT_BOUNCE_TO_IP
%token  SPAMD REJECT_MESSAGE SERVERS_ID ID_PREFIX GREY_PREFIX WHITE_PREFIX RSPAMD_METRIC ALSO_CHECK DIFF_DIR CHECK_SYMBOLS SYMBOLS_DIR
%token  BEANSTALK ID_REGEXP LIFETIME COPY_SERVER GREYLISTED_MESSAGE SPAMD_SOFT_FAIL STRICT_AUTH
%token	TRACE_SYMBOL TRACE_ADDR WHITELIST_FROM SPAM_HEADER SPAM_HEADER_VALUE SPAMD_GREYLIST EXTENDED_SPAM_HEADERS
%token  DKIM_SECTION DKIM_KEY DKIM_DOMAIN DKIM_SELECTOR DKIM_HEADER_CANON DKIM_BODY_CANON
%token  DKIM_SIGN_ALG DKIM_RELAXED DKIM_SIMPLE DKIM_SHA1 DKIM_SHA256 DKIM_AUTH_ONLY COPY_PROBABILITY
%token  SEND_BEANSTALK_SPAM_EXTRA_DIFF DKIM_FOLD_HEADER SPAMD_RETRY_COUNT SPAMD_RETRY_TIMEOUT SPAMD_TEMPFAIL
%token  SPAMD_NEVER_REJECT TEMPFILES_MODE USE_REDIS REDIS DKIM_SIGN_NETWORKS OUR_NETWORKS SPAM_BAR_CHAR
%token  SPAM_NO_AUTH_HEADER PASSWORD DBNAME SPAMD_SETTINGS_ID SPAMD_SPAM_ADD_HEADER
%token  COPY_FULL COPY_CHANNEL SPAM_CHANNEL ENABLE EQPLUS COMPRESSION DKIM_RSPAMD_SIGN
%token  EXTENDED_HEADERS_RCPT

%type	<string>	STRING
%type	<string>	QUOTEDSTRING
%type	<string>	FILENAME
%type	<string>	REGEXP
%type   <string>  	SOCKCRED
%type	<string>	IPADDR IPNETWORK
%type	<string>	HOSTPORT
%type 	<string>	ip_net cache_hosts clamav_addr spamd_addr bounce_addr
%type	<string>	DOMAIN_STR
%type	<limit>		SIZELIMIT
%type	<flag>		FLAG
%type	<bucket>	BUCKET;
%type	<seconds>	SECONDS;
%type	<number>	NUMBER;
%type	<frac>		FLOAT;
%type	<frac>		prob_num;
%%

input:
	empty
	| command separator input
	;

separator:
	SEMICOLON
	| empty
	;

empty:
	/* %empty */
	;

command	:
	tempdir
	| tempfiles_mode
	| strictauth
	| pidfile
	| clamav
	| spamd
	| spf
	| bindsock
	| maxsize
	| usedcc
	| cache
	| limits
	| greylisting
	| whitelist
	| dkim
	| use_redis
	| our_networks
	| syslog_name
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

tempfiles_mode:
	TEMPFILES_MODE EQSIGN NUMBER {
		/*
		 * We likely have here decimal number, so we need to treat it as
		 * octal one that means oct -> dec conversion
		 */
		int i = 1;
		cfg->tempfiles_mode = 0;

		while ($3 > 0) {
			cfg->tempfiles_mode += $3 % 10 * i;
			i *= 8;
			$3 /= 10;
		}
	}
	| TEMPFILES_MODE EQSIGN QUOTEDSTRING {
		char *err_str;

		cfg->tempfiles_mode = strtoul ($3, &err_str, 8);

		if (err_str != NULL && *err_str != '\0') {
			yyerror ("yyparse: cannot convert \"%s\" to octal number: %s", $3,
					strerror (errno));
			YYERROR;
		}

		free ($3);
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

clamav:
	CLAMAV OBRACE clamavbody EBRACE
	| CLAMAV OBRACE empty EBRACE
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
	| clamav_whitelist
	;

clamav_servers:
	SERVERS EQSIGN {
		cfg->clamav_servers_num = 0;
	} clamav_server
	| SERVERS EQPLUS clamav_server
	;

clamav_server:
	clamav_params
	| clamav_server COMMA clamav_params
	| empty
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
clamav_whitelist:
	WHITELIST EQSIGN clamav_ip_list
	;

clamav_ip_list:
	clamav_ip
	| clamav_ip_list COMMA clamav_ip
	;

clamav_ip:
	ip_net {
		if (add_ip_radix (&cfg->clamav_whitelist, $1) == 0) {
			YYERROR;
		}
	}
	;

spamd:
	SPAMD OBRACE spamdbody EBRACE
	| SPAMD OBRACE empty EBRACE
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
	| spamd_spam_add_header
	| spamd_spam_header
	| spamd_spam_header_value
	| spamd_greylist
	| extended_spam_headers
	| spamd_retry_count
	| spamd_retry_timeout
	| spamd_tempfail
	| spamd_never_reject
	| spam_bar_char
	| spam_no_auth_header
	| spamd_settings_id
	| spamd_compression
	| spamd_extended_rcpts
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

		if (cfg->diff_dir) {
			free (cfg->diff_dir);
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

		if (cfg->symbols_dir) {
			free (cfg->symbols_dir);
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
	SERVERS EQSIGN {
		cfg->spamd_servers_num = 0;
	}
	spamd_server
	| SERVERS EQPLUS spamd_server
	;

spamd_server:
	spamd_params
	| spamd_server COMMA spamd_params
	| empty
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
	WHITELIST EQSIGN {
		if (cfg->spamd_whitelist) {
			radix_destroy_compressed (cfg->spamd_whitelist);
			cfg->spamd_whitelist = NULL;
		}
	} spamd_ip_list
	| WHITELIST EQPLUS spamd_ip_list
	;

spamd_ip_list:
	spamd_ip
	| spamd_ip_list COMMA spamd_ip
	| empty
	;

spamd_ip:
	ip_net {
		if (add_ip_radix (&cfg->spamd_whitelist, $1) == 0) {
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
		cfg->spamd_soft_fail = $3;
	}
	;

spamd_never_reject:
	SPAMD_NEVER_REJECT EQSIGN FLAG {
		cfg->spamd_never_reject = $3;
	}
	;

spamd_spam_add_header:
	SPAMD_SPAM_ADD_HEADER EQSIGN FLAG {
		cfg->spamd_spam_add_header = $3;
	}
	;

extended_spam_headers:
	EXTENDED_SPAM_HEADERS EQSIGN FLAG {
		cfg->extended_spam_headers = $3;
	}
	;

spamd_greylist:
	SPAMD_GREYLIST EQSIGN FLAG {
		cfg->spamd_greylist = $3;
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
spam_bar_char:
	SPAM_BAR_CHAR EQSIGN QUOTEDSTRING {
		free (cfg->spam_bar_char);
		cfg->spam_bar_char = $3;
	}
	;
spam_no_auth_header:
	SPAM_NO_AUTH_HEADER EQSIGN FLAG {
		cfg->spam_no_auth_header = $3;
	}
	;

spamd_settings_id:
	SPAMD_SETTINGS_ID EQSIGN QUOTEDSTRING {
		free (cfg->spamd_settings_id);
		cfg->spamd_settings_id = $3;
	}
	;

spamd_compression:
	COMPRESSION EQSIGN FLAG {
		cfg->compression_enable = $3;
	}
	;

spamd_extended_rcpts:
	EXTENDED_HEADERS_RCPT EQSIGN {
		clear_rcpt_whitelist (&cfg->extended_rcpts);
	} extended_rcpt_list
	| EXTENDED_HEADERS_RCPT EQPLUS extended_rcpt_list
	;
extended_rcpt_list:
	STRING {
		add_rcpt_whitelist (&cfg->extended_rcpts, $1);
	}
	| QUOTEDSTRING {
		add_rcpt_whitelist (&cfg->extended_rcpts, $1);
	}
	| extended_rcpt_list COMMA STRING {
		add_rcpt_whitelist (&cfg->extended_rcpts, $3);
	}
	| extended_rcpt_list COMMA QUOTEDSTRING {
		add_rcpt_whitelist (&cfg->extended_rcpts, $3);
	}
	| empty
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
		yywarn ("spf support is removed from rmilter");
	}
	| STRING {
		yywarn ("spf support is removed from rmilter");
	}
	| QUOTEDSTRING {
		yywarn ("spf support is removed from rmilter");
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
		cfg->use_dcc = $3;
	}
	;

greylisting:
	GREYLISTING OBRACE greylistingbody EBRACE
	| GREYLISTING OBRACE empty EBRACE
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
	| greylisting_enable
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
	WHITELIST EQSIGN {
		if (cfg->grey_whitelist_tree) {
			radix_destroy_compressed (cfg->grey_whitelist_tree);
			cfg->grey_whitelist_tree = NULL;
		}
	}
	greylisting_ip_list
	| WHITELIST EQPLUS greylisting_ip_list
	;

greylisting_ip_list:
	greylisting_ip
	| greylisting_ip_list COMMA greylisting_ip
	;

greylisting_ip:
	ip_net {
		if (add_ip_radix (&cfg->grey_whitelist_tree, $1) == 0) {
			YYERROR;
		}
	}
	;

greylisted_message:
	GREYLISTED_MESSAGE EQSIGN QUOTEDSTRING {
		free (cfg->greylisted_message);
		cfg->greylisted_message = $3;
	}
	;

greylisting_enable:
	ENABLE EQSIGN FLAG {
		cfg->greylisting_enable = $3;
	}
	;

ip_net:
	IPADDR
	| IPNETWORK
	| QUOTEDSTRING
	;

cache:
	MEMCACHED OBRACE cachebody EBRACE
	| REDIS { cfg->cache_use_redis = 1; } OBRACE cachebody EBRACE
	;

cachebody:
	cahcebody_commands
	| empty
	;
cahcebody_commands:
	cachecmd SEMICOLON
	| cahcebody_commands cachecmd SEMICOLON
	;

cachecmd:
	cache_grey_servers
	| cache_white_servers
	| cache_limits_servers
	| cache_id_servers
	| cache_spam_servers
	| cache_copy_servers
	| cache_connect_timeout
	| cache_error_time
	| cache_dead_time
	| cache_maxerrors
	| cache_protocol
	| cache_id_prefix
	| cache_grey_prefix
	| cache_white_prefix
	| cache_password
	| cache_dbname
	| cache_spam_channel
	| cache_copy_channel
	| cache_copy_probability
	;

cache_grey_servers:
	SERVERS_GREY EQSIGN
	{
		cfg->cache_servers_grey_num = 0;
	}
	cache_grey_server
	| SERVERS_GREY EQPLUS cache_grey_server
	;

cache_grey_server:
	cache_grey_params
	| cache_grey_server COMMA cache_grey_params
	| empty
	;

cache_grey_params:
	OBRACE cache_hosts COMMA cache_hosts EBRACE {
		if (!add_cache_server (cfg, $2, $4, CACHE_SERVER_GREY)) {
			yyerror ("yyparse: add_cache_server");
			YYERROR;
		}
		free ($2);
		free ($4);
	}
	| cache_hosts {
		if (!add_cache_server (cfg, $1, NULL, CACHE_SERVER_GREY)) {
			yyerror ("yyparse: add_cache_server");
			YYERROR;
		}
		free ($1);
	}
	;

cache_white_servers:
	SERVERS_WHITE EQSIGN
	{
		cfg->cache_servers_white_num = 0;
	}
	cache_white_server
	| SERVERS_WHITE EQPLUS cache_white_server
	;

cache_white_server:
	cache_white_params
	| cache_white_server COMMA cache_white_params
	;

cache_white_params:
	OBRACE cache_hosts COMMA cache_hosts EBRACE {
		if (!add_cache_server (cfg, $2, $4, CACHE_SERVER_WHITE)) {
			yyerror ("yyparse: add_cache_server");
			YYERROR;
		}
		free ($2);
		free ($4);
	}
	| cache_hosts {
		if (!add_cache_server (cfg, $1, NULL, CACHE_SERVER_WHITE)) {
			yyerror ("yyparse: add_cache_server");
			YYERROR;
		}
		free ($1);
	}
	;

cache_limits_servers:
	SERVERS_LIMITS EQSIGN
	{
		cfg->cache_servers_limits_num = 0;
	}
	cache_limits_server
	| SERVERS_LIMITS EQPLUS cache_limits_server
	;

cache_limits_server:
	cache_limits_params
	| cache_limits_server COMMA cache_limits_params
	| empty
	;

cache_limits_params:
	cache_hosts {
		if (!add_cache_server (cfg, $1, NULL, CACHE_SERVER_LIMITS)) {
			yyerror ("yyparse: add_cache_server");
			YYERROR;
		}
		free ($1);
	}
	;

cache_id_servers:
	SERVERS_ID EQSIGN
	{
		cfg->cache_servers_id_num = 0;
	}
	cache_id_server
	| SERVERS_ID EQPLUS cache_id_server
	;

cache_id_server:
	cache_id_params
	| cache_id_server COMMA cache_id_params
	| empty
	;

cache_id_params:
	cache_hosts {
		if (!add_cache_server (cfg, $1, NULL, CACHE_SERVER_ID)) {
			yyerror ("yyparse: add_cache_server");
			YYERROR;
		}
		free ($1);
	}
	;

cache_copy_servers:
	SERVERS_COPY EQSIGN
	{
		cfg->cache_servers_copy_num = 0;
	}
	cache_copy_server
	| SERVERS_COPY EQPLUS cache_copy_server
	;

cache_copy_server:
	cache_copy_params
	| cache_copy_server COMMA cache_copy_params
	| empty
	;

cache_copy_params:
	cache_hosts {
		if (!add_cache_server (cfg, $1, NULL, CACHE_SERVER_COPY)) {
			yyerror ("yyparse: add_cache_server");
			YYERROR;
		}
		free ($1);
	}
	;

cache_spam_servers:
	SERVERS_SPAM EQSIGN
	{
		cfg->cache_servers_spam_num = 0;
	}
	cache_spam_server
	| SERVERS_SPAM EQPLUS cache_spam_server
	;

cache_spam_server:
	cache_spam_params
	| cache_spam_server COMMA cache_spam_params
	| empty
	;

cache_spam_params:
	cache_hosts {
		if (!add_cache_server (cfg, $1, NULL, CACHE_SERVER_SPAM)) {
			yyerror ("yyparse: add_cache_server");
			YYERROR;
		}
		free ($1);
	}
	;

cache_hosts:
	STRING
	| QUOTEDSTRING
	| IPADDR
	| DOMAIN_STR
	| HOSTPORT
	;
cache_error_time:
	ERROR_TIME EQSIGN NUMBER {
		cfg->cache_error_time = $3;
	}
	;
cache_dead_time:
	DEAD_TIME EQSIGN NUMBER {
		cfg->cache_dead_time = $3;
	}
	;
cache_maxerrors:
	MAXERRORS EQSIGN NUMBER {
		cfg->cache_maxerrors = $3;
	}
	;
cache_connect_timeout:
	CONNECT_TIMEOUT EQSIGN SECONDS {
		cfg->cache_connect_timeout = $3;
	}
	;

cache_protocol:
	PROTOCOL EQSIGN STRING {
		/* Do nothing now*/
	}
	;
cache_id_prefix:
	ID_PREFIX EQSIGN QUOTEDSTRING {
		free (cfg->id_prefix);
		cfg->id_prefix = $3;
	}
	;

cache_grey_prefix:
	GREY_PREFIX EQSIGN QUOTEDSTRING {
		free (cfg->grey_prefix);
		cfg->grey_prefix = $3;
	}
	;

cache_white_prefix:
	WHITE_PREFIX EQSIGN QUOTEDSTRING {
		free (cfg->white_prefix);
		cfg->white_prefix = $3;
	}
	;

cache_password:
	PASSWORD EQSIGN QUOTEDSTRING {
		free (cfg->cache_password);
		cfg->cache_password = $3;
	}
	;

cache_dbname:
	DBNAME EQSIGN QUOTEDSTRING {
		free (cfg->cache_dbname);
		cfg->cache_dbname = $3;
	}
	;

cache_copy_channel:
	COPY_CHANNEL EQSIGN QUOTEDSTRING {
		free (cfg->cache_copy_channel);
		cfg->cache_copy_channel = $3;
	}
	;

cache_copy_probability:
	COPY_PROBABILITY EQSIGN prob_num {
		if ($3 < 0) {
			YYERROR;
		}
		if ($3 > 1.0) {
			if ($3 > 100.0) {
				YYERROR;
			}
			cfg->cache_copy_prob = $3 / 100.0;
		}
		else {
			cfg->cache_copy_prob = $3;
		}
	}
	;
prob_num:
	NUMBER { $$ = (double)$1; }
	| FLOAT
	;
cache_spam_channel:
	SPAM_CHANNEL EQSIGN QUOTEDSTRING {
		free (cfg->cache_spam_channel);
		cfg->cache_spam_channel = $3;
	}
	;

limits:
	LIMITS OBRACE limitsbody EBRACE
	| LIMITS OBRACE empty EBRACE
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
	| limit_enable
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
	LIMIT_WHITELIST EQSIGN {
		if (cfg->limit_whitelist_tree) {
			radix_destroy_compressed (cfg->limit_whitelist_tree);
			cfg->limit_whitelist_tree = NULL;
		}
	}
	whitelist_ip_list
	| LIMIT_WHITELIST EQPLUS whitelist_ip_list
	;
whitelist_ip_list:
	ip_net {
		if (add_ip_radix (&cfg->limit_whitelist_tree, $1) == 0) {
			YYERROR;
		}
	}
	| whitelist_ip_list COMMA ip_net {
		if (add_ip_radix (&cfg->limit_whitelist_tree, $3) == 0) {
			YYERROR;
		}
	}
	| empty
	;

limit_whitelist_rcpt:
	LIMIT_WHITELIST_RCPT EQSIGN {
		clear_rcpt_whitelist (&cfg->wlist_rcpt_limit);
	} whitelist_rcpt_list
	| LIMIT_WHITELIST_RCPT EQPLUS whitelist_rcpt_list
	;
whitelist_rcpt_list:
	STRING {
		add_rcpt_whitelist (&cfg->wlist_rcpt_limit, $1);
	}
	| QUOTEDSTRING {
		add_rcpt_whitelist (&cfg->wlist_rcpt_limit, $1);
	}
	| whitelist_rcpt_list COMMA STRING {
		add_rcpt_whitelist (&cfg->wlist_rcpt_limit, $3);
	}
	| whitelist_rcpt_list COMMA QUOTEDSTRING {
		add_rcpt_whitelist (&cfg->wlist_rcpt_limit, $3);
	}
	| empty
	;

limit_bounce_addrs:
	LIMIT_BOUNCE_ADDRS EQSIGN {
		struct addr_list_entry *t, *tmp;

		HASH_ITER (hh, cfg->bounce_addrs, t, tmp) {
			HASH_DEL (cfg->bounce_addrs, t);
			free (t->addr);
			free (t);
		}
	} bounce_addr_list
	| LIMIT_BOUNCE_ADDRS EQPLUS bounce_addr_list
	;
bounce_addr_list:
	bounce_addr {
		struct addr_list_entry *t;
		t = calloc (1, sizeof (struct addr_list_entry));
		t->addr = strdup ($1);
		t->len = strlen (t->addr);
		HASH_ADD_KEYPTR(hh, cfg->bounce_addrs, t->addr, t->len, t);
	}
	| bounce_addr_list COMMA bounce_addr {
		struct addr_list_entry *t;
		t = calloc (1, sizeof (struct addr_list_entry));
		t->addr = strdup ($3);
		t->len = strlen (t->addr);
		HASH_ADD_KEYPTR(hh, cfg->bounce_addrs, t->addr, t->len, t);
	}
	| empty
	;

bounce_addr:
	STRING
	| QUOTEDSTRING

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

limit_enable:
	ENABLE EQSIGN FLAG {
		cfg->ratelimit_enable = $3;
	}
	;

whitelist:
	WHITELIST EQSIGN {
		clear_rcpt_whitelist (&cfg->wlist_rcpt_global);
	} whitelist_list
	| WHITELIST EQPLUS whitelist_list
	;
whitelist_list:
	STRING {
		add_rcpt_whitelist (&cfg->wlist_rcpt_global, $1);
	}
	| QUOTEDSTRING {
		add_rcpt_whitelist (&cfg->wlist_rcpt_global, $1);
	}
	| whitelist_list COMMA STRING {
		add_rcpt_whitelist (&cfg->wlist_rcpt_global, $3);
	}
	| whitelist_list COMMA QUOTEDSTRING {
		add_rcpt_whitelist (&cfg->wlist_rcpt_global, $3);
	}
	| empty
	;


dkim:
	DKIM_SECTION OBRACE dkimbody EBRACE
	| DKIM_SECTION OBRACE empty EBRACE
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
	| dkim_sign_networks
	| dkim_enable
	| dkim_rspamd_sign
	;

dkim_domain:
	DKIM_DOMAIN OBRACE dkim_domain_body EBRACE {
		if (cur_domain == NULL || cur_domain->domain == NULL ||
			cur_domain->selector == NULL) {
			yyerror ("yyparse: incomplete dkim definition");
			YYERROR;
		}
		if (!cur_domain->is_loaded) {
			/* Assume it as wildcard domain */
			cur_domain->is_wildcard = 1;
		}


		rmilter_str_lc (cur_domain->domain, strlen (cur_domain->domain));
		HASH_ADD_KEYPTR (hh, cfg->dkim_domains, cur_domain->domain,
			strlen (cur_domain->domain), cur_domain);
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
			else {
				yyerror ("yyparse: cannot open: %s, %s", $3, strerror (errno));
				YYERROR;
			}
		}
		cur_domain->keyfile = strdup ($3);
	}
	| DKIM_KEY EQSIGN QUOTEDSTRING {
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
			else {
				yyerror ("yyparse: cannot open: %s, %s", $3, strerror (errno));
				YYERROR;
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
		cfg->dkim_auth_only = $3;
	}
	;

dkim_fold_header:
	DKIM_FOLD_HEADER EQSIGN FLAG {
		cfg->dkim_fold_header = $3;
	}
	;
dkim_sign_networks:
	DKIM_SIGN_NETWORKS EQSIGN {
		if (cfg->dkim_ip_tree) {
			radix_destroy_compressed (cfg->dkim_ip_tree);
			cfg->dkim_ip_tree = NULL;
		}
	} dkim_ip_list
	| DKIM_SIGN_NETWORKS EQPLUS dkim_ip_list
	;
dkim_ip_list:
	ip_net {
		if (add_ip_radix (&cfg->dkim_ip_tree, $1) == 0) {
			YYERROR;
		}
	}
	| dkim_ip_list COMMA ip_net {
		if (add_ip_radix (&cfg->dkim_ip_tree, $3) == 0) {
			YYERROR;
		}
	}
	| empty
	;

dkim_enable:
	ENABLE EQSIGN FLAG {
		cfg->dkim_enable = $3;
	}
	;

dkim_rspamd_sign:
	DKIM_RSPAMD_SIGN EQSIGN FLAG {
		cfg->rspamd_dkim_sign = $3;
	}
	;

use_redis:
	USE_REDIS EQSIGN FLAG {
		cfg->cache_use_redis = $3;
	}
	;

our_networks:
	OUR_NETWORKS EQSIGN {
		if (cfg->our_networks) {
			radix_destroy_compressed (cfg->our_networks);
			cfg->our_networks = NULL;
		}
	}our_networks_list
	| OUR_NETWORKS EQPLUS our_networks_list
	;

our_networks_list:
	our_networks_elt
	| our_networks_list COMMA our_networks_elt
	| empty
	;

our_networks_elt:
	ip_net {
		if (add_ip_radix (&cfg->our_networks, $1) == 0) {
			YYERROR;
		}
	}
	;

syslog_name:
	SYSLOGNAME EQSIGN STRING {
		cfg->syslog_name = $3;
	}
	| SYSLOGNAME EQSIGN QUOTEDSTRING {
		cfg->syslog_name = $3;
	}
	;
%%
/*
 * vi:ts=4
 */
