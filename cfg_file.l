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

%}

%option  noyywrap

%%
logfile							return LOGFILE;
pidfile							return PIDFILE;
rule							return RULE;
clamav							return CLAMAV;
spf_domains						return SPF;
bind_socket						return BINDSOCK;
\"								return QUOTE;
\{								return OBRACE;
\}								return EBRACE;
;								return SEMICOLON;
,								return COMMA;
=								return EQSIGN;
\n								/* ignore EOL */;
[ \t]+							/* ignore whitespace */;
[a-zA-Z][a-zA-Z]*				return lookup (yytext);
\/.+\/[a-zA-Z]?					yylval.string=strdup(yytext); return REGEXP;
[a-zA-Z0-9\/.-]+				yylval.string=strdup(yytext); return FILENAME;
unix|local:[a-zA-Z0-9\/.-]+ 	yylval.string=strdup(yytext); return UNIXSOCK;
inet:[0-9]+@[a-zA-Z0-9.-]+		yylval.string=strdup(yytext); return TCPSOCK;
%%
