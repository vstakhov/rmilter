%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include "cfg_file.h"
#include "cfg_yacc.h"

struct keywords {
	const char  *k_name;
	int      k_val;
};

static int
kw_cmp(const void *k, const void *e)
{
	return (strcasecmp(k, ((struct keywords *)e)->k_name));
}


static int
lookup(char *s)
{
	/* keep sorted */
	static const struct keywords keywords[] = {
		{ "accept", ACCEPT },
		{ "body",   BODY },
		{ "connect",    CONNECT },
		{ "discard",    DISCARD },
		{ "envfrom",    ENVFROM },
		{ "envrcpt",    ENVRCPT },
		{ "header", HEADER },
		{ "helo",   HELO },
		{ "not",    NOT },
		{ "quarantine", QUARANTINE },
		{ "reject", REJECTL },
		{ "tempfail",   TEMPFAIL },
	};
	const struct keywords *p;

	p = bsearch(s, keywords, sizeof(keywords) / sizeof(keywords[0]),
		sizeof(keywords[0]), &kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

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
	unsigned int result = 0;
	char *err_str;

	if (!t || *t == '\0') return 0;

	result = strtoul (t, &err_str, 10);

	if (*err_str != '\0') {
		/* Seconds */
		if (*err_str == 's' || *err_str == 'S') {
			result *= 1000;
		}
	}

	return result;
}

static char
parse_flag (const char *str)
{
	if (!str || !*str) return -1;

	if (*str == '1' && *(str + 1) == '\0') {
		return 1;
	}

	if ((*str == 'Y' || *str == 'y') &&
		(*(str + 1) == 'E' || *(str + 1) == 'e') &&
		(*(str + 2) == 'S' || *(str + 2) == 's') &&
		*(str + 3) == '\0') {
		return 1;		
	}

	if (*str == '0' && *(str + 1) == '\0') {
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
tempdir							return TEMPDIR;
pidfile							return PIDFILE;
rule							return RULE;
clamav|clamav_servers			return CLAMAV;
clamav_connect_timeout			return CLAMAV_CONNECT_TIMEOUT;
clamav_port_timeout				return CLAMAV_PORT_TIMEOUT;
clamav_results_timeout			return CLAMAV_RESULTS_TIMEOUT;
memcached|memcached_servers		return MEMCACHED;
spf_domains						return SPF;
bind_socket						return BINDSOCK;
max_size						return MAXSIZE;
use_dcc							return USEDCC;

limits							return LIMITS;
limit_to						return LIMIT_TO;
limit_to_ip						return LIMIT_TO_IP;
limit_to_ip_from				return LIMIT_TO_IP_FROM;
limit_whitelist_ip				return LIMIT_WHITELIST_IP;
limit_whitelist_rcpt			return LIMIT_WHITELIST_RCPT;
limit_bounce_addrs				return LIMIT_BOUNCE_ADDRS;
limit_bounce_to					return LIMIT_BOUNCE_TO;
limit_bounce_to_ip				return LIMIT_BOUNCE_TO_IP; 

\"								return QUOTE;
\{								return OBRACE;
\}								return EBRACE;
;								return SEMICOLON;
,								return COMMA;
=								return EQSIGN;
yes|YES|no|NO|0|1				yylval.flag=parse_flag(yytext); return FLAG;
\n								/* ignore EOL */;
[ \t]+							/* ignore whitespace */;
\".+\"							yylval.string=strdup(yytext); return QUOTEDSTRING;
[0-9]+[kKmMgG]?					yylval.limit=parse_limit(yytext); return SIZELIMIT;
[0-9]+[sS]|[0-9]+[mM][sS]		yylval.seconds=parse_seconds(yytext); return SECONDS;
[0-9]+:[0-9]+[.]?[0-9]*			parse_bucket(yytext, &yylval.bucket); return BUCKET;
unix:[a-zA-Z0-9\/.-]+ 			yylval.string=strdup(yytext); return SOCKCRED;
local:[a-zA-Z0-9\/.-]+ 			yylval.string=strdup(yytext); return SOCKCRED;
inet:[0-9]+@[a-zA-Z0-9.-]+		yylval.string=strdup(yytext); return SOCKCRED;
[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}	yylval.string=strdup(yytext); return IPADDR;
[a-zA-Z<][a-zA-Z@+>_-]*			yylval.string=strdup(yytext); return lookup (yytext);
\/[^/\n]+\/						yylval.string=strdup(yytext); return REGEXP;
[a-zA-Z0-9].[a-zA-Z0-9\/.-]+	yylval.string=strdup(yytext); return DOMAIN;
[a-zA-Z0-9.-]+:[0-9]{1,5}		yylval.string=strdup(yytext); return HOSTPORT;
[a-zA-Z0-9\/.-]+				yylval.string=strdup(yytext); return FILENAME;
%%
/* 
 * vi:ts=4 
 */
