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


#ifndef CFG_FILE_H
#define CFG_FILE_H

#include "config.h"
#include "util.h"
#include "pcre.h"
#include "upstream.h"
#include "radix.h"
#include "uthash.h"

#ifdef WITH_DKIM
#include <dkim.h>
#endif

#define COND_CONNECT_FLAG 0x1
#define COND_HELO_FLAG 0x2
#define COND_ENVFROM_FLAG 0x4
#define COND_ENVRCPT_FLAG 0x8
#define COND_HEADER_FLAG 0x10
#define COND_BODY_FLAG 0x20

#define MAX_SPF_DOMAINS 1024
#define MAX_CLAMAV_SERVERS 32
#define MAX_SPAMD_SERVERS 32
#define MAX_CACHE_SERVERS 32
#define DEFAULT_MEMCACHED_PORT 11211
#define DEFAULT_CLAMAV_PORT 3310
#define DEFAULT_SPAMD_PORT 11333
/* Clamav timeouts */
#define DEFAULT_CLAMAV_CONNECT_TIMEOUT 1000
#define DEFAULT_CLAMAV_PORT_TIMEOUT 3000
#define DEFAULT_CLAMAV_RESULTS_TIMEOUT 20000
/* Spamd timeouts */
#define DEFAULT_SPAMD_CONNECT_TIMEOUT 1000
#define DEFAULT_SPAMD_RESULTS_TIMEOUT 20000
#define DEFAULT_SPAMD_RETRY_TIMEOUT 1000
#define DEFAULT_SPAMD_RETRY_COUNT 5
#define DEFAULT_RSPAMD_METRIC "default"
/* Memcached timeouts */
#define DEFAULT_MEMCACHED_CONNECT_TIMEOUT 1000
/* Upstream timeouts */
#define DEFAULT_UPSTREAM_ERROR_TIME 10
#define DEFAULT_UPSTREAM_DEAD_TIME 300
#define DEFAULT_UPSTREAM_MAXERRORS 10

#define CACHE_SERVER_LIMITS 0
#define CACHE_SERVER_GREY 1
#define CACHE_SERVER_WHITE 2
#define CACHE_SERVER_ID 3
#define CACHE_SERVER_COPY 4
#define CACHE_SERVER_SPAM 5

#define DEFAUL_SPAMD_REJECT "Spam message rejected; If this is not spam contact abuse team"
#define DEFAULT_GREYLISTED_MESSAGE "Try again later"
#define DEFAULT_SPAM_HEADER "X-Spam"
#define DEFAULT_SPAM_HEADER_VALUE "yes"

#define MD5_SIZE 16

#define yyerror parse_err
#define yywarn parse_warn
#define CFG_RLOCK() do { pthread_rwlock_rdlock (&cfg_mtx); } while (0)
#define CFG_WLOCK() do { pthread_rwlock_wrlock (&cfg_mtx); } while (0)
#define CFG_UNLOCK() do { pthread_rwlock_unlock (&cfg_mtx); } while (0)

extern pthread_rwlock_t cfg_mtx;

enum spamd_type {
	SPAMD_RSPAMD = 0
};

typedef struct bucket_s {
	unsigned int burst;
	double rate;
} bucket_t;

struct clamav_server {
	struct upstream up;
	int port;
	char *name;
};

struct spamd_server {
	struct upstream up;
	enum spamd_type type;
	char *name;
	int port;
};

struct cache_server {
	struct upstream up;
	char *addr;
	int port;
	bool is_redis;
};

struct beanstalk_server {
	struct upstream up;
	int port;
	char *name;
};

struct addr_list_entry {
	char *addr;
	size_t len;
	UT_hash_handle hh;
};

struct dkim_hash_entry {
	char *name;
	UT_hash_handle hh;
};

struct dkim_domain_entry {
	char *domain;
	char *selector;
	char *key;
	char *keyfile;
	size_t keylen;
	UT_hash_handle hh;
	unsigned int is_wildcard;
	unsigned int is_loaded;
};

struct whitelisted_rcpt_entry {
	char *rcpt;
	size_t len;
	enum {
		WLIST_RCPT_USER = 0,
		WLIST_RCPT_DOMAIN,
		WLIST_RCPT_USERDOMAIN
	} type;
	UT_hash_handle hh;
};

struct config_file {
	char *cfg_name;
	char *pid_file;
	char *temp_dir;

	char *sock_cred;
	size_t sizelimit;

	struct clamav_server clamav_servers[MAX_CLAMAV_SERVERS];
	unsigned int clamav_servers_num;
	unsigned int clamav_error_time;
	unsigned int clamav_dead_time;
	unsigned int clamav_maxerrors;
	unsigned int clamav_connect_timeout;
	unsigned int clamav_port_timeout;
	unsigned int clamav_results_timeout;
	radix_compressed_t *clamav_whitelist;
	unsigned int tempfiles_mode;

	struct spamd_server spamd_servers[MAX_SPAMD_SERVERS];
	unsigned int spamd_servers_num;
	struct spamd_server extra_spamd_servers[MAX_SPAMD_SERVERS];
	unsigned int extra_spamd_servers_num;
	unsigned int spamd_error_time;
	unsigned int spamd_dead_time;
	unsigned int spamd_maxerrors;
	unsigned int spamd_connect_timeout;
	unsigned int spamd_results_timeout;
	radix_compressed_t *spamd_whitelist;
	char *spamd_reject_message;
	char *rspamd_metric;
	char *diff_dir;
	char *check_symbols;
	char *symbols_dir;
	char *trace_symbol;
	char *trace_addr;
	char *spam_header;
	char *spam_header_value;
	char *spam_bar_char;
	char *spamd_settings_id;

	unsigned int spamd_retry_timeout;
	unsigned int spamd_retry_count;

	pcre* special_mid_re;

	struct cache_server cache_servers_limits[MAX_CACHE_SERVERS];
	unsigned int  cache_servers_limits_num;
	struct cache_server cache_servers_grey[MAX_CACHE_SERVERS];
	unsigned int  cache_servers_grey_num;
	struct cache_server cache_servers_white[MAX_CACHE_SERVERS];
	unsigned int  cache_servers_white_num;
	struct cache_server cache_servers_id[MAX_CACHE_SERVERS];
	unsigned int  cache_servers_id_num;
	struct cache_server cache_servers_copy[MAX_CACHE_SERVERS];
	unsigned int  cache_servers_copy_num;
	struct cache_server cache_servers_spam[MAX_CACHE_SERVERS];
	unsigned int  cache_servers_spam_num;
	unsigned int cache_error_time;
	unsigned int cache_dead_time;
	unsigned int cache_maxerrors;
	unsigned int cache_connect_timeout;
	char *cache_password;
	char *cache_dbname;
	char *cache_spam_channel;
	char *cache_copy_channel;

	double cache_copy_prob;

	unsigned send_cache_copy:1;
	unsigned send_cache_spam:1;
	unsigned send_cache_headers:1;
	unsigned send_cache_extra_diff:1;
	unsigned cache_use_redis:1;
	unsigned spamd_soft_fail:1;
	unsigned spamd_greylist:1;
	unsigned spamd_spam_add_header:1;
	unsigned spam_no_auth_header:1;
	unsigned extended_spam_headers:1;
	unsigned spamd_temp_fail:1;
	unsigned spamd_never_reject:1;
	unsigned use_dcc:1;
	unsigned strict_auth:1;
	unsigned weighted_clamav:1;
	unsigned greylisting_enable:1;
	unsigned ratelimit_enable:1;
	unsigned dkim_enable:1;

	/* limits section */
	bucket_t limit_to;
	bucket_t limit_to_ip;
	bucket_t limit_to_ip_from;
	bucket_t limit_bounce_to;
	bucket_t limit_bounce_to_ip;

	struct whitelisted_rcpt_entry *wlist_rcpt_limit;
	struct whitelisted_rcpt_entry *wlist_rcpt_global;
	struct addr_list_entry *bounce_addrs;

	unsigned int greylisting_timeout;
	unsigned int greylisting_expire;
	unsigned int whitelisting_expire;
	char *id_prefix;
	char *grey_prefix;
	char *white_prefix;
	char *greylisted_message;
	radix_compressed_t *grey_whitelist_tree;
	radix_compressed_t *limit_whitelist_tree;
	radix_compressed_t *our_networks;

	/* DKIM section */
	struct dkim_domain_entry *dkim_domains;
	unsigned dkim_relaxed_header:1;
	unsigned dkim_relaxed_body:1;
	unsigned dkim_sign_sha256:1;
	unsigned dkim_auth_only:1;
	unsigned dkim_fold_header:1;
	radix_compressed_t *dkim_ip_tree;
#ifdef WITH_DKIM
	DKIM_LIB *dkim_lib;
	struct dkim_hash_entry *headers;
#endif

	/* Number of config reloads */
	unsigned int serial;
};

int add_cache_server (struct config_file *cf, char *str, char *str2, int type);
int add_clamav_server (struct config_file *cf, char *str);
int add_spamd_server (struct config_file *cf, char *str, int is_extra);
void init_defaults (struct config_file *cfg);
void free_config (struct config_file *cfg);
int add_ip_radix (radix_compressed_t **tree, char *ipnet);
void add_rcpt_whitelist (struct config_file *cfg, const char *rcpt, int is_global);
int is_whitelisted_rcpt (struct config_file *cfg, const char *str, int is_global);
void clear_rcpt_whitelist (struct config_file *cfg, bool is_global);
char *trim_quotes (char *in);

int yylex (void);
int yyparse (void);
void yyrestart (FILE *);

void parse_err (const char *fmt, ...);
void parse_warn (const char *fmt, ...);

struct mlfi_priv;

#endif /* ifdef CFG_FILE_H */
/*
 * vi:ts=4
 */
