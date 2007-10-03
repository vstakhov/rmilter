%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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

%}

%option  noyywrap

%%
^#.*							/* ignore comments */;
tempdir							return TEMPDIR;
pidfile							return PIDFILE;
rule							return RULE;
clamav							return CLAMAV;
spf_domains						return SPF;
bind_socket						return BINDSOCK;
max_size						return MAXSIZE;
\"								return QUOTE;
\{								return OBRACE;
\}								return EBRACE;
;								return SEMICOLON;
,								return COMMA;
=								return EQSIGN;
\n								/* ignore EOL */;
[ \t]+							/* ignore whitespace */;
\".+\"							yylval.string=strdup(yytext); return QUOTEDSTRING;
[0-9]+[kKmMgG]?					yylval.limit=parse_limit(yytext); return LIMIT;
unix:[a-zA-Z0-9\/.-]+ 			yylval.string=strdup(yytext); return SOCKCRED;
local:[a-zA-Z0-9\/.-]+ 			yylval.string=strdup(yytext); return SOCKCRED;
inet:[0-9]+@[a-zA-Z0-9.-]+		yylval.string=strdup(yytext); return SOCKCRED;
[a-zA-Z][a-zA-Z]*				yylval.string=strdup(yytext); return lookup (yytext);
\/[^/\n]+\/						yylval.string=strdup(yytext); return REGEXP;
[a-zA-Z0-9].[a-zA-Z0-9\/.-]+	yylval.string=strdup(yytext); return DOMAIN;
[a-zA-Z0-9\/.-]+				yylval.string=strdup(yytext); return FILENAME;
%%
