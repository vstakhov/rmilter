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

#include <assert.h>
#include "config.h"

#include "pcre.h"
#include "cfg_file.h"
#include "spf.h"
#include "rmilter.h"

extern int yylineno;
extern char *yytext;

void
parse_err (const char *fmt, ...)
{
	va_list aq;
	char logbuf[BUFSIZ], readbuf[32];
	int r;

	va_start (aq, fmt);
	rmilter_strlcpy (readbuf, yytext, sizeof (readbuf));

	r = snprintf (logbuf, sizeof (logbuf), "config file parse error! line: %d, text: %s, reason: ", yylineno, readbuf);
	r += vsnprintf (logbuf + r, sizeof (logbuf) - r, fmt, aq);

	va_end (aq);
	fprintf (stderr,"%s\n", logbuf);
	syslog (LOG_ERR, "%s", logbuf);
}

void
parse_warn (const char *fmt, ...)
{
	va_list aq;
	char logbuf[BUFSIZ], readbuf[32];
	int r;

	va_start (aq, fmt);
	rmilter_strlcpy (readbuf, yytext, sizeof (readbuf));

	r = snprintf (logbuf, sizeof (logbuf), "config file parse warning! line: %d, text: %s, reason: ", yylineno, readbuf);
	r += vsnprintf (logbuf + r, sizeof (logbuf) - r, fmt, aq);

	va_end (aq);
	syslog (LOG_ERR, "%s", logbuf);
}


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

	return rmilter_strlcpy (*dst, src, len + 1);
}

int
add_memcached_server (struct config_file *cf, char *str, char *str2, int type)
{
	char *cur_tok, *err_str;
	struct memcached_server *mc = NULL;
	struct hostent *he;
	uint16_t port;

	if (str == NULL) return 0;

	if (type == MEMCACHED_SERVER_GREY) {
		if(cf->memcached_servers_grey_num == MAX_MEMCACHED_SERVERS) {
			yyerror ("yyparse: maximum number of memcached servers is reached %d", MAX_MEMCACHED_SERVERS);
			return 0;
		}

		mc = &cf->memcached_servers_grey[cf->memcached_servers_grey_num];
	}
	else if (type == MEMCACHED_SERVER_WHITE) {
		if(cf->memcached_servers_white_num == MAX_MEMCACHED_SERVERS) {
			yyerror ("yyparse: maximum number of whitelist memcached servers is reached %d", MAX_MEMCACHED_SERVERS);
			return 0;
		}

		mc = &cf->memcached_servers_white[cf->memcached_servers_white_num];
	}
	else if (type == MEMCACHED_SERVER_LIMITS) {
		if(cf->memcached_servers_limits_num == MAX_MEMCACHED_SERVERS) {
			yyerror ("yyparse: maximum number of limits memcached servers is reached %d", MAX_MEMCACHED_SERVERS);
			return 0;
		}

		mc = &cf->memcached_servers_limits[cf->memcached_servers_limits_num];
	}
	else if (type == MEMCACHED_SERVER_ID) {
		if(cf->memcached_servers_id_num == MAX_MEMCACHED_SERVERS) {
			yyerror ("yyparse: maximum number of id memcached servers is reached %d", MAX_MEMCACHED_SERVERS);
			return 0;
		}

		mc = &cf->memcached_servers_id[cf->memcached_servers_id_num];
	}
	if (mc == NULL) return 0;

	cur_tok = strsep (&str, ":");

	if (cur_tok == NULL || *cur_tok == '\0') return 0;

	/* cur_tok - server name, str - server port */
	if (str == NULL) {
		port = htons(DEFAULT_MEMCACHED_PORT);
	}
	else {
		port = htons ((uint16_t)strtoul (str, &err_str, 10));
		if (*err_str != '\0') {
			yyerror ("yyparse: bad memcached port: %s", str);
			return 0;
		}
	}

	if (!inet_aton (cur_tok, &mc->addr[0])) {
		/* Try to call gethostbyname */
		he = gethostbyname (cur_tok);
		if (he == NULL) {
			yyerror ("yyparse: bad memcached host: %s", cur_tok);
			return 0;
		}
		else {
			memcpy((char *)&mc->addr[0], he->h_addr, sizeof(struct in_addr));
		}
	}
	mc->port[0] = port;

	if (str2 == NULL) {
		mc->num = 1;
	}
	else {
		mc->num = 2;
		cur_tok = strsep (&str2, ":");

		if (cur_tok == NULL || *cur_tok == '\0') return 0;

		/* cur_tok - server name, str - server port */
		if (str2 == NULL) {
			port = htons(DEFAULT_MEMCACHED_PORT);
		}
		else {
			port = htons ((uint16_t)strtoul (str2, &err_str, 10));
			if (*err_str != '\0') {
				yyerror ("yyparse: bad memcached port: %s", str2);
				return 0;
			}
		}

		if (!inet_aton (cur_tok, &mc->addr[1])) {
			/* Try to call gethostbyname */
			he = gethostbyname (cur_tok);
			if (he == NULL) {
				yyerror ("yyparse: bad memcached host: %s", cur_tok);
				return 0;
			}
			else {
				memcpy((char *)&mc->addr[1], he->h_addr, sizeof(struct in_addr));
			}
		}
		mc->port[1] = port;
	}

	mc->alive[0] = 1;
	mc->alive[1] = 1;

	if (type == MEMCACHED_SERVER_GREY) {
		cf->memcached_servers_grey_num++;
	}
	else if (type == MEMCACHED_SERVER_WHITE) {
		cf->memcached_servers_white_num++;
	}
	else if (type == MEMCACHED_SERVER_LIMITS) {
		cf->memcached_servers_limits_num++;
	}
	else if (type == MEMCACHED_SERVER_ID) {
		cf->memcached_servers_id_num++;
	}

	return 1;
}

int
add_clamav_server (struct config_file *cf, char *str)
{
	char *cur_tok, *err_str;
	struct clamav_server *srv;
	struct hostent *he;

	if (str == NULL) return 0;

	cur_tok = strsep (&str, ":");

	if (cur_tok == NULL || *cur_tok == '\0') return 0;

	if (cf->clamav_servers_num == MAX_CLAMAV_SERVERS) {
		yyerror ("yyparse: maximum number of clamav servers is reached %d", MAX_CLAMAV_SERVERS);
	}

	srv = &cf->clamav_servers[cf->clamav_servers_num];

	if (srv == NULL) return 0;

	if (cur_tok[0] == '/' || cur_tok[0] == '.') {
		srv->sock.unix_path = strdup (cur_tok);
		srv->sock_type = AF_UNIX;
		srv->name = srv->sock.unix_path;
		if (str != NULL && *str != '\0') {
			srv->up.priority = strtoul (str, &err_str, 10);
			if (*err_str != '\0') {
				yyerror ("yyparse: bad clamav port %s",
						str);
				return 0;
			}
			cf->weighted_clamav = 1;
		}

		cf->clamav_servers_num++;
		return 1;

	} else {
		if (str == '\0') {
			srv->sock.inet.port = htons (DEFAULT_CLAMAV_PORT);
		}
		else {
			srv->sock.inet.port = htons ((uint16_t)strtoul (str, &err_str, 10));
			if (*err_str != '\0') {
				return 0;
			}

		}

		if (!inet_aton (cur_tok, &srv->sock.inet.addr)) {
			/* Try to call gethostbyname */
			he = gethostbyname (cur_tok);
			if (he == NULL) {
				yyerror ("yyparse: bad clamav host %s",
						cur_tok);
				return 0;
			}
			else {
				srv->name = strdup (cur_tok);
				memcpy((char *)&srv->sock.inet.addr, he->h_addr, sizeof(struct in_addr));
			}
		}
		/* Try to parse priority */
		cur_tok = strsep (&str, ":");
		if (str != NULL && *str != '\0') {
			srv->up.priority = strtoul (str, &err_str, 10);
			if (*err_str != '\0') {
				yyerror ("yyparse: bad clamav priority %s",
						str);
				return 0;
			}
			cf->weighted_clamav = 1;
		}

		srv->sock_type = AF_INET;
		cf->clamav_servers_num++;
		return 1;
	}

	return 0;
}

int
add_spamd_server (struct config_file *cf, char *str, int is_extra)
{
	char *cur_tok, *err_str;
	struct spamd_server *srv;
	struct hostent *he;

	if (str == NULL) return 0;

	if (is_extra) {
		if (cf->extra_spamd_servers_num == MAX_SPAMD_SERVERS) {
			yyerror ("yyparse: maximum number of spamd servers is reached %d", MAX_SPAMD_SERVERS);
			return -1;
		}
	}
	else {
		if (cf->spamd_servers_num == MAX_SPAMD_SERVERS) {
			yyerror ("yyparse: maximum number of spamd servers is reached %d", MAX_SPAMD_SERVERS);
			return -1;
		}
	}

	if (is_extra) {
		srv = &cf->extra_spamd_servers[cf->extra_spamd_servers_num];
	}
	else {
		srv = &cf->spamd_servers[cf->spamd_servers_num];
	}

	if (*str == 'r' && *(str + 1) == ':') {
		srv->type = SPAMD_RSPAMD;
		str += 2;
	}
	else {
		srv->type = SPAMD_SPAMASSASSIN;
	}


	cur_tok = strsep (&str, ":");

	if (cur_tok == NULL || *cur_tok == '\0') return 0;

	if (cur_tok[0] == '/' || cur_tok[0] == '.') {
		srv->sock.unix_path = strdup (cur_tok);
		srv->sock_type = AF_UNIX;
		srv->name = srv->sock.unix_path;

		if (is_extra) {
			cf->extra_spamd_servers_num++;
		}
		else {
			cf->spamd_servers_num++;
		}
		return 1;

	} else {
		if (str == '\0') {
			srv->sock.inet.port = htons (DEFAULT_SPAMD_PORT);
		}
		else {
			srv->sock.inet.port = htons ((uint16_t)strtoul (str, &err_str, 10));
			if (*err_str != '\0') {
				yyerror ("yyparse: bad spamd port %s",
						str);
				return 0;
			}
		}

		if (!inet_aton (cur_tok, &srv->sock.inet.addr)) {
			/* Try to call gethostbyname */
			he = gethostbyname (cur_tok);
			if (he == NULL) {
				yyerror ("yyparse: bad spamd host %s",
						cur_tok);
				return 0;
			}
			else {
				memcpy((char *)&srv->sock.inet.addr, he->h_addr, sizeof(struct in_addr));
			}
		}
		srv->name = strdup (cur_tok);

		srv->sock_type = AF_INET;
		if (is_extra) {
			cf->extra_spamd_servers_num++;
		}
		else {
			cf->spamd_servers_num++;
		}
		return 1;
	}

	return 0;
}

int
add_beanstalk_server (struct config_file *cf, char *str, int type)
{
	char *cur_tok, *err_str;
	struct beanstalk_server *srv;
	struct hostent *he;

	if (str == NULL) return 0;

	cur_tok = strsep (&str, ":");

	if (cur_tok == NULL || *cur_tok == '\0') return 0;

	if (type == 1) {
		cf->copy_server = malloc (sizeof (struct beanstalk_server));
		srv = cf->copy_server;
	}
	else if (type == 2) {
		cf->spam_server = malloc (sizeof (struct beanstalk_server));
		srv = cf->spam_server;
	}
	else {
		if (cf->beanstalk_servers_num == MAX_BEANSTALK_SERVERS) {
			yyerror ("yyparse: maximum number of beanstalk servers is reached %d", MAX_BEANSTALK_SERVERS);
		}

		srv = &cf->beanstalk_servers[cf->beanstalk_servers_num];
	}

	if (srv == NULL) return 0;

	if (str == '\0') {
		srv->port = htons (DEFAULT_BEANSTALK_PORT);
	}
	else {
		srv->port = htons ((uint16_t)strtoul (str, &err_str, 10));
		if (*err_str != '\0') {
			yyerror ("yyparse: bad beanstalk port %s",
					str);
			return 0;
		}
	}

	if (!inet_aton (cur_tok, &srv->addr)) {
		/* Try to call gethostbyname */
		he = gethostbyname (cur_tok);
		if (he == NULL) {
			yyerror ("yyparse: bad beanstalk host %s",
					cur_tok);
			return 0;
		}
		else {
			srv->name = strdup (cur_tok);
			memcpy((char *)&srv->addr, he->h_addr, sizeof(struct in_addr));
		}
		if (type == 0) {
			cf->beanstalk_servers_num ++;
		}
		return 1;
	}
	else {
		srv->name = strdup (cur_tok);
		if (type == 0) {
			cf->beanstalk_servers_num ++;
		}
		return 1;
	}


	return 0;
}

struct action *
create_action (enum action_type type, const char *message)
{
	struct action *new;
	size_t len = strlen (message);

	if (message == NULL) return NULL;

	new = (struct action *)malloc (sizeof (struct action));

	if (new == NULL) return NULL;

	new->type = type;

	new->message = (char *)malloc (len + 1);

	if (new->message == NULL) return NULL;

	rmilter_strlcpy (new->message, message, len + 1);

	return new;
}

struct condition *
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

int
add_spf_domain (struct config_file *cfg, char *domain)
{
	if (!domain) return 0;

	if (cfg->spf_domains_num > MAX_SPF_DOMAINS) {
		yyerror ("yyparse: too many domains, cannot add %s",
				domain);
		return 0;
	}

	cfg->spf_domains[cfg->spf_domains_num] = domain;
	cfg->spf_domains_num ++;

	return 1;
}

int
add_ip_radix (radix_tree_t *tree, char *ipnet)
{
	uint32_t mask = 0xFFFFFFFF;
	uint32_t ip;
	char *token;
	struct in_addr ina;
	int k;

	token = strsep (&ipnet, "/");

	if (ipnet != NULL) {
		k = atoi (ipnet);
		if (k > 32 || k < 0) {
			yyerror ("add_ip_radix: invalid netmask value: %d", k);
			k = 32;
		}
		k = 32 - k;
		mask = mask << k;
	}

	if (inet_aton (token, &ina) == 0) {
		yyerror ("add_ip_radix: invalid ip address: %s", token);
		return 0;
	}

	ip = ntohl((uint32_t)ina.s_addr);
	k = radix32tree_insert (tree, ip, mask, 1);
	if (k == -1) {
		yyerror ("add_ip_radix: cannot insert ip to tree: %s, mask %X", inet_ntoa (ina), mask);
		return 0;
	}
	else if (k == 1) {
		yywarn ("add_ip_radix: ip %s, mask %X, value already exists", inet_ntoa (ina), mask);
	}

	return 1;
}

static void
add_hashed_header (const char *name, struct dkim_hash_entry **hash)
{
	struct dkim_hash_entry *new;

	new = malloc (sizeof (struct dkim_hash_entry));
	new->name = strdup (name);
	HASH_ADD_KEYPTR (hh, *hash, new->name, strlen (new->name), new);
}

void
init_defaults (struct config_file *cfg)
{
	LIST_INIT (&cfg->rules);
	cfg->wlist_rcpt_global = NULL;
	cfg->wlist_rcpt_limit = NULL;
	LIST_INIT (&cfg->bounce_addrs);

	cfg->clamav_connect_timeout = DEFAULT_CLAMAV_CONNECT_TIMEOUT;
	cfg->clamav_port_timeout = DEFAULT_CLAMAV_PORT_TIMEOUT;
	cfg->clamav_results_timeout = DEFAULT_CLAMAV_RESULTS_TIMEOUT;
	cfg->memcached_connect_timeout = DEFAULT_MEMCACHED_CONNECT_TIMEOUT;
	cfg->beanstalk_connect_timeout = DEFAULT_MEMCACHED_CONNECT_TIMEOUT;
	cfg->spamd_connect_timeout = DEFAULT_SPAMD_CONNECT_TIMEOUT;
	cfg->spamd_results_timeout = DEFAULT_SPAMD_RESULTS_TIMEOUT;

	cfg->clamav_error_time = DEFAULT_UPSTREAM_ERROR_TIME;
	cfg->clamav_dead_time = DEFAULT_UPSTREAM_DEAD_TIME;
	cfg->clamav_maxerrors = DEFAULT_UPSTREAM_MAXERRORS;

	cfg->spamd_error_time = DEFAULT_UPSTREAM_ERROR_TIME;
	cfg->spamd_dead_time = DEFAULT_UPSTREAM_DEAD_TIME;
	cfg->spamd_maxerrors = DEFAULT_UPSTREAM_MAXERRORS;
	cfg->spamd_reject_message = strdup (DEFAUL_SPAMD_REJECT);
	cfg->rspamd_metric = strdup (DEFAULT_RSPAMD_METRIC);
	cfg->spam_header = strdup (DEFAULT_SPAM_HEADER);
	cfg->spam_header_value = strdup (DEFAULT_SPAM_HEADER_VALUE);
	cfg->spamd_retry_count = DEFAULT_SPAMD_RETRY_COUNT;
	cfg->spamd_retry_timeout = DEFAULT_SPAMD_RETRY_TIMEOUT;
	cfg->spamd_temp_fail = 0;

	cfg->memcached_error_time = DEFAULT_UPSTREAM_ERROR_TIME;
	cfg->memcached_dead_time = DEFAULT_UPSTREAM_DEAD_TIME;
	cfg->memcached_maxerrors = DEFAULT_UPSTREAM_MAXERRORS;
	cfg->memcached_protocol = UDP_TEXT;

	cfg->beanstalk_error_time = DEFAULT_UPSTREAM_ERROR_TIME;
	cfg->beanstalk_dead_time = DEFAULT_UPSTREAM_DEAD_TIME;
	cfg->beanstalk_maxerrors = DEFAULT_UPSTREAM_MAXERRORS;
	cfg->beanstalk_protocol = BEANSTALK_TCP_TEXT;
	cfg->beanstalk_lifetime = DEFAULT_BEANSTALK_LIFETIME;
	cfg->copy_server = NULL;
	cfg->spam_server = NULL;

	cfg->grey_whitelist_tree = radix_tree_create ();
	cfg->limit_whitelist_tree = radix_tree_create ();
	cfg->spamd_whitelist = radix_tree_create ();
	cfg->greylisted_message = strdup (DEFAULT_GREYLISTED_MESSAGE);

	cfg->spf_domains = (char **) calloc (MAX_SPF_DOMAINS, sizeof (char *));
	cfg->awl_enable = 0;
	cfg->beanstalk_copy_prob = 100.0;

	cfg->spamd_soft_fail = 1;
	cfg->spamd_greylist = 1;

	cfg->dkim_auth_only = 1;
	cfg->pid_file = NULL;
	cfg->tempfiles_mode = 00600;

#if 0
	/* Init static defaults */
	white_from_abuse.addr = "abuse";
	white_from_abuse.len = sizeof ("abuse") - 1;
	white_from_postmaster.addr = "postmaster";
	white_from_postmaster.len = sizeof ("postmaster") - 1;
	LIST_INSERT_HEAD (&cfg->whitelist_static, &white_from_abuse, next);
	LIST_INSERT_HEAD (&cfg->whitelist_static, &white_from_postmaster, next);
#endif

#ifdef WITH_DKIM
	cfg->dkim_lib = dkim_init (NULL, NULL);
	/* Add recommended by rfc headers */
	add_hashed_header ("from", &cfg->headers);
	add_hashed_header ("sender", &cfg->headers);
	add_hashed_header ("reply-to", &cfg->headers);
	add_hashed_header ("subject", &cfg->headers);
	add_hashed_header ("date", &cfg->headers);
	add_hashed_header ("message-id", &cfg->headers);
	add_hashed_header ("to", &cfg->headers);
	add_hashed_header ("cc", &cfg->headers);
	add_hashed_header ("date", &cfg->headers);
	add_hashed_header ("mime-version", &cfg->headers);
	add_hashed_header ("content-type", &cfg->headers);
	add_hashed_header ("content-transfer-encoding", &cfg->headers);
	add_hashed_header ("resent-to", &cfg->headers);
	add_hashed_header ("resent-cc", &cfg->headers);
	add_hashed_header ("resent-from", &cfg->headers);
	add_hashed_header ("resent-sender", &cfg->headers);
	add_hashed_header ("resent-message-id", &cfg->headers);
	add_hashed_header ("in-reply-to", &cfg->headers);
	add_hashed_header ("references", &cfg->headers);
	add_hashed_header ("list-id", &cfg->headers);
	add_hashed_header ("list-owner", &cfg->headers);
	add_hashed_header ("list-unsubscribe", &cfg->headers);
	add_hashed_header ("list-subscribe", &cfg->headers);
	add_hashed_header ("list-post", &cfg->headers);
	/* TODO: make it configurable */
#endif
}

void
free_config (struct config_file *cfg)
{
	unsigned int i;
	struct rule *cur, *tmp_rule;
	struct condition *cond, *tmp_cond;
	struct addr_list_entry *addr_cur, *addr_tmp;
	struct whitelisted_rcpt_entry *rcpt_cur, *rcpt_tmp;

	if (cfg->pid_file) {
		free (cfg->pid_file);
	}
	if (cfg->temp_dir) {
		free (cfg->temp_dir);
	}
	if (cfg->sock_cred) {
		free (cfg->sock_cred);
	}

	if (cfg->spf_domains) {
		for (i = 0; i < MAX_SPF_DOMAINS; i++) {
			free (cfg->spf_domains[i]);
		}
		free (cfg->spf_domains);
	}

	if (cfg->special_mid_re) {
		pcre_free (cfg->special_mid_re);
	}

	for (i = 0; i < cfg->clamav_servers_num; i++) {
		free (cfg->clamav_servers[i].name);
	}
	for (i = 0; i < cfg->spamd_servers_num; i++) {
		free (cfg->spamd_servers[i].name);
	}
	/* Free rules list */
	LIST_FOREACH_SAFE (cur, &cfg->rules, next, tmp_rule) {
		LIST_FOREACH_SAFE (cond, cur->conditions, next, tmp_cond) {
			if (!cond->args[0].empty) {
				if (cond->args[0].re != NULL) {
					pcre_free (cond->args[0].re);
				}
				if (cond->args[0].src != NULL) {
					free (cond->args[0].src);
				}
			}
			if (!cond->args[1].empty) {
				if (cond->args[1].re != NULL) {
					pcre_free (cond->args[1].re);
				}
				if (cond->args[1].src != NULL) {
					free (cond->args[1].src);
				}
			}
			LIST_REMOVE (cond, next);
			free (cond);
		}
		if (cur->act->message) {
			free (cur->act->message);
		}
		free (cur->act);
		LIST_REMOVE (cur, next);
		free (cur);
	}
	/* Free whitelists and bounce list*/
	HASH_ITER (hh, cfg->wlist_rcpt_global, rcpt_cur, rcpt_tmp) {
		HASH_DEL (cfg->wlist_rcpt_global, rcpt_cur);
		free (rcpt_cur->rcpt);
		free (rcpt_cur);
	}
	HASH_ITER (hh, cfg->wlist_rcpt_limit, rcpt_cur, rcpt_tmp) {
		HASH_DEL (cfg->wlist_rcpt_limit, rcpt_cur);
		free (rcpt_cur->rcpt);
		free (rcpt_cur);
	}
	LIST_FOREACH_SAFE (addr_cur, &cfg->bounce_addrs, next, addr_tmp) {
		if (addr_cur->addr) {
			free (addr_cur->addr);
		}
		LIST_REMOVE (addr_cur, next);
		free (addr_cur);
	}

	radix_tree_free (cfg->grey_whitelist_tree);
	free (cfg->grey_whitelist_tree);

	radix_tree_free (cfg->spamd_whitelist);
	free (cfg->spamd_whitelist);

	radix_tree_free (cfg->limit_whitelist_tree);
	free (cfg->limit_whitelist_tree);

	if (cfg->spamd_reject_message) {
		free (cfg->spamd_reject_message);
	}
	if (cfg->rspamd_metric) {
		free (cfg->rspamd_metric);
	}
	if (cfg->spam_header) {
		free (cfg->spam_header);
	}
	if (cfg->spam_header_value) {
		free (cfg->spam_header_value);
	}
	if (cfg->id_prefix) {
		free (cfg->id_prefix);
	}
	if (cfg->grey_prefix) {
		free (cfg->grey_prefix);
	}
	if (cfg->white_prefix) {
		free (cfg->white_prefix);
	}
	if (cfg->copy_server) {
		free (cfg->copy_server);
	}
	if (cfg->spam_server) {
		free (cfg->spam_server);
	}
	if (cfg->greylisted_message) {
		free (cfg->greylisted_message);
	}

	if (cfg->awl_enable && cfg->awl_hash != NULL) {
		free (cfg->awl_hash->pool);
		free (cfg->awl_hash);
	}


#ifdef WITH_DKIM
	struct dkim_hash_entry *curh, *tmph;
	struct dkim_domain_entry *curd, *tmpd;

	if (cfg->dkim_lib) {
		dkim_close (cfg->dkim_lib);
	}
	HASH_ITER (hh, cfg->headers, curh, tmph) {
		HASH_DEL (cfg->headers, curh);  /* delete; users advances to next */
		free (curh->name);
		free (curh);
	}
	HASH_ITER (hh, cfg->dkim_domains, curd, tmpd) {
		HASH_DEL (cfg->dkim_domains, curd);  /* delete; users advances to next */
		if (curd->key != MAP_FAILED && curd->key != NULL) {
			munmap (curd->key, curd->keylen);
		}
		if (curd->domain) {
			free (curd->domain);
		}
		if (curd->selector) {
			free (curd->selector);
		}
		if (curd->keyfile) {
			free (curd->keyfile);
		}
		free (curd);
	}
#endif
}

void
add_rcpt_whitelist (struct config_file *cfg, const char *rcpt, int is_global)
{
	struct whitelisted_rcpt_entry *t;
	t = (struct whitelisted_rcpt_entry *)malloc (sizeof (struct whitelisted_rcpt_entry));
	if (*rcpt == '@') {
		t->type = WLIST_RCPT_DOMAIN;
		rcpt ++;
	}
	else if (strchr (rcpt, '@') != NULL) {
		t->type = WLIST_RCPT_USERDOMAIN;
	}
	else {
		t->type = WLIST_RCPT_USER;
	}
	t->rcpt = strdup (rcpt);
	t->len = strlen (t->rcpt);
	if (is_global) {
		HASH_ADD_KEYPTR (hh, cfg->wlist_rcpt_global, t->rcpt, t->len, t);
	}
	else {
		HASH_ADD_KEYPTR (hh, cfg->wlist_rcpt_limit, t->rcpt, t->len, t);
	}
}

int
is_whitelisted_rcpt (struct config_file *cfg, const char *str, int is_global)
{
	int len;
	struct whitelisted_rcpt_entry *entry, *list;
	char rcptbuf[ADDRLEN + 1], *domain;

	if (*str == '<') {
		str ++;
	}

	len = strcspn (str, ">");
	rmilter_strlcpy (rcptbuf, str, MIN (len + 1, sizeof (rcptbuf)));
	if (len > 0) {
		if (is_global) {
			list = cfg->wlist_rcpt_global;
		}
		else {
			list = cfg->wlist_rcpt_limit;
		}
		/* Initially search for userdomain */
		HASH_FIND_STR (list, rcptbuf, entry, strncasecmp);
		if (entry != NULL && entry->type == WLIST_RCPT_USERDOMAIN) {
			return 1;
		}
		domain = strchr (rcptbuf, '@');
		if (domain == NULL && entry != NULL && entry->type == WLIST_RCPT_USER) {
			return 1;
		}
		/* Search for user */
		if (domain != NULL) {
			*domain = '\0';
		}
		HASH_FIND_STR (list, rcptbuf, entry, strncasecmp);
		if (entry != NULL && entry->type == WLIST_RCPT_USER) {
			return 1;
		}
		if (domain != NULL) {
			/* Search for domain */
			domain ++;
			HASH_FIND_STR (list, domain, entry, strncasecmp);
			if (entry != NULL && entry->type == WLIST_RCPT_DOMAIN) {
				return 1;
			}
		}
	}

	return 0;
}

char *
trim_quotes (char *in)
{
	char *res = in;
	size_t len;

	assert (in != NULL);

	len = strlen (in);

	if (*in == '"') {
		res = strdup (in + 1);
		len = strlen (res);
		free (in);
	}

	if (len > 1 && res[len - 1] == '"') {
		res[len - 1] = '\0';
	}

	return res;
}

/*
 * vi:ts=4
 */
