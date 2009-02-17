%x incl

%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include "cfg_file.h"
#include "cfg_yacc.h"

#define MAX_INCLUDE_DEPTH 10
YY_BUFFER_STATE include_stack[MAX_INCLUDE_DEPTH];
int line_stack[MAX_INCLUDE_DEPTH];
int include_stack_ptr = 0;

static size_t
parse_limit (const char *limit)
{
	size_t result = 0;
	char *err_str;

	if (!limit || *limit == '\0') return 0;

	result = strtoul (limit, &err_str, 10);

	if (*err_str != '\0') {
		/* Megabytes */
		if (*err_str == 'm' || *err_str == 'M') {
			result *= 1048576L;
		}
		/* Kilobytes */
		else if (*err_str == 'k' || *err_str == 'K') {
			result *= 1024;
		}
		/* Gigabytes */
		else if (*err_str == 'g' || *err_str == 'G') {
			result *= 1073741824L;
		}
	}

	return result;
}

static unsigned int
parse_seconds (const char *t)
{
	unsigned long int result = 0;
	char *err_str;

	if (!t || *t == '\0') return 0;

	result = strtoul (t, &err_str, 10);

	if (*err_str != '\0') {
		/* Seconds */
		if (*err_str == 's' || *err_str == 'S') {
			result *= 1000;
		}
		/* Minutes */
		if (*err_str == 'm' || *err_str == 'M') {
			result *= 60 * 1000;
		}
		/* Hours */
		if (*err_str == 'h' || *err_str == 'H') {
			result *= 60 * 60 * 1000;
		}
		/* Days */
		if (*err_str == 'd' || *err_str == 'D') {
			result *= 24 * 60 * 60 * 1000;
		}
	}

	return result;
}

static char
parse_flag (const char *str)
{
	if (!str || !*str) return -1;

	if ((*str == 'y' || *str == 'Y') && *(str + 1) == '\0') {
		return 1;
	}

	if ((*str == 'Y' || *str == 'y') &&
		(*(str + 1) == 'E' || *(str + 1) == 'e') &&
		(*(str + 2) == 'S' || *(str + 2) == 's') &&
		*(str + 3) == '\0') {
		return 1;		
	}

	if ((*str == 'n' || *str == 'N') && *(str + 1) == '\0') {
		return 0;
	}

	if ((*str == 'N' || *str == 'n') &&
		(*(str + 1) == 'O' || *(str + 1) == 'o') &&
		*(str + 2) == '\0') {
		return 0;		
	}

	return -1;
}

static void
parse_bucket (char *str, bucket_t *bucket)
{
	char *cur_tok, *err_str;

	bucket->burst = 0;
	bucket->rate = 0;

	cur_tok = strsep (&str, ":");
	if (cur_tok == NULL || *cur_tok == '\0' || str == NULL || *str == '\0') {
		yywarn ("parse_bucket: invalid bucket value %s", str);
		return;
	}

	bucket->burst = strtol (cur_tok, &err_str, 10);
	if (*err_str != '\0') {
		yywarn ("parse_bucket: invalid bucket value %s", err_str);
		bucket->burst = 0;
		return;
	}
	bucket->rate = strtod (str, &err_str);
	if (*err_str != '\0') {
		yywarn ("parse_bucket: invalid bucket value %s", err_str);
		bucket->rate = 0;
		return;
	}
}

%}

%option noyywrap
%option yylineno

%%
^[ \t]*#.*						/* ignore comments */;
.include						BEGIN(incl);
tempdir							return TEMPDIR;
pidfile							return PIDFILE;
rule							return RULE;
clamav							return CLAMAV;
spamd							return SPAMD;
type							return TYPE;
spamassassin					return SPAMASSASSIN;
rspamd							return RSPAMD;
rspamd_metric					return RSPAMD_METRIC;
reject_message					return REJECT_MESSAGE;
servers							return SERVERS;
servers_limits					return SERVERS_LIMITS;
servers_grey					return SERVERS_GREY;
servers_white					return SERVERS_WHITE;
servers_id						return SERVERS_ID;
error_time						return ERROR_TIME;
dead_time						return DEAD_TIME;
maxerrors						return MAXERRORS;
connect_timeout					return CONNECT_TIMEOUT;
port_timeout					return PORT_TIMEOUT;
results_timeout					return RESULTS_TIMEOUT;
id_prefix						return ID_PREFIX;
grey_prefix						return GREY_PREFIX;
white_prefix					return WHITE_PREFIX;
memcached						return MEMCACHED;
protocol						return PROTOCOL;
spf_domains						return SPF;
bind_socket						return BINDSOCK;
max_size						return MAXSIZE;
use_dcc							return USEDCC;
greylisting						return GREYLISTING;
whitelist						return WHITELIST;
timeout							return TIMEOUT;
expire_white					return EXPIRE_WHITE;
expire							return EXPIRE;
awl_enable						return AWL_ENABLE;
awl_hits						return AWL_HITS;
awl_ttl							return AWL_TTL;
awl_pool						return AWL_POOL;

limits							return LIMITS;
limit_to						return LIMIT_TO;
limit_to_ip						return LIMIT_TO_IP;
limit_to_ip_from				return LIMIT_TO_IP_FROM;
limit_whitelist					return LIMIT_WHITELIST;
limit_whitelist_rcpt			return LIMIT_WHITELIST_RCPT;
limit_bounce_addrs				return LIMIT_BOUNCE_ADDRS;
limit_bounce_to					return LIMIT_BOUNCE_TO;
limit_bounce_to_ip				return LIMIT_BOUNCE_TO_IP; 

accept							return ACCEPT;
body							return BODY;
connect							return CONNECT;
discard							return DISCARD;
envfrom							return ENVFROM;
envrcpt							return ENVRCPT;
header							return HEADER;
helo							return HELO;
not								return NOT;
quarantine						return QUARANTINE;
reject							return REJECTL;
tempfail						return TEMPFAIL;


\"								return QUOTE;
\{								return OBRACE;
\}								return EBRACE;
;								return SEMICOLON;
,								return COMMA;
=								return EQSIGN;
yes|YES|no|NO|[yY]|[nN]			yylval.flag=parse_flag(yytext); return FLAG;
\n								/* ignore EOL */;
[ \t]+							/* ignore whitespace */;
\".+\"							yylval.string=strdup(yytext); return QUOTEDSTRING;
[0-9]+							yylval.number=strtol(yytext, NULL, 10); return NUMBER;
[0-9]+[kKmMgG]?					yylval.limit=parse_limit(yytext); return SIZELIMIT;
[0-9]+[sShHdD]|[0-9]+[mM][sS]	yylval.seconds=parse_seconds(yytext); return SECONDS;
[0-9]+:[0-9]+[.]?[0-9]*			parse_bucket(yytext, &yylval.bucket); return BUCKET;
unix:[a-zA-Z0-9\/.-]+ 			yylval.string=strdup(yytext); return SOCKCRED;
local:[a-zA-Z0-9\/.-]+ 			yylval.string=strdup(yytext); return SOCKCRED;
inet:[0-9]+@[a-zA-Z0-9.-]+		yylval.string=strdup(yytext); return SOCKCRED;
[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}	yylval.string=strdup(yytext); return IPADDR;
[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}	yylval.string=strdup(yytext); return IPNETWORK;
\/[^/\n]+\/						yylval.string=strdup(yytext); return REGEXP;
[a-zA-Z<][a-zA-Z@+>_-]*			yylval.string=strdup(yytext); return STRING;
[a-zA-Z0-9].[a-zA-Z0-9\/.-]+	yylval.string=strdup(yytext); return DOMAIN;
[a-zA-Z0-9.-]+:[0-9]{1,5}		yylval.string=strdup(yytext); return HOSTPORT;
[a-zA-Z0-9\/.-]+				yylval.string=strdup(yytext); return FILENAME;
<incl>[ \t]*      				/* eat the whitespace */
<incl>[^ \t\n]+   { 
		/* got the include file name */
		if ( include_stack_ptr >= MAX_INCLUDE_DEPTH ) {
			yyerror ("yylex: includes nested too deeply" );
			return -1;
		}

		line_stack[include_stack_ptr] = yylineno;
		include_stack[include_stack_ptr++] = YY_CURRENT_BUFFER;

		yylineno = 1;
		yyin = fopen (yytext, "r");

		if (!yyin) {
			yyerror ("yylex: cannot open include file");
			return -1;
		}

		yy_switch_to_buffer (yy_create_buffer (yyin, YY_BUF_SIZE));

		BEGIN(INITIAL);
}

<<EOF>> {
		if ( --include_stack_ptr < 0 ) {
			include_stack_ptr = 0;
			yylineno = 1;
			yyterminate ();
		}
		else {
			yy_delete_buffer (YY_CURRENT_BUFFER);
			yy_switch_to_buffer (include_stack[include_stack_ptr] );
			yylineno = line_stack[include_stack_ptr];
		}
}

%%
/* 
 * vi:ts=4 
 */
