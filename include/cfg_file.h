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
#include "beanstalk.h"
#include "radix.h"
#include "awl.h"

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
#define MAX_CLAMAV_SERVERS 48
#define MAX_SPAMD_SERVERS 48
#define MAX_MEMCACHED_SERVERS 48
#define MAX_BEANSTALK_SERVERS 48
#define DEFAULT_MEMCACHED_PORT 11211
#define DEFAULT_CLAMAV_PORT 3310
#define DEFAULT_SPAMD_PORT 11333
#define DEFAULT_BEANSTALK_PORT 11300
#define DEFAULT_BEANSTALK_LIFETIME 172800
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

#define MEMCACHED_SERVER_LIMITS 0
#define MEMCACHED_SERVER_GREY 1
#define MEMCACHED_SERVER_WHITE 2
#define MEMCACHED_SERVER_ID 3

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

enum { VAL_UNDEF=0, VAL_TRUE, VAL_FALSE };
enum condition_type {
	COND_CONNECT = 0,
	COND_HELO,
	COND_ENVFROM,
	COND_ENVRCPT,
	COND_HEADER,
	COND_BODY,
	COND_MAX
};

enum action_type {
	ACTION_REJECT,
	ACTION_TEMPFAIL,
	ACTION_QUARANTINE,
	ACTION_DISCARD,
	ACTION_ACCEPT
};

enum spamd_type {
	SPAMD_RSPAMD = 0
};

typedef struct bucket_s {
	unsigned int burst;
	double rate;
} bucket_t;

struct action {
	enum action_type type;
	char *message;
};

struct condition {
	struct cond_arg {
		char    *src;
		int  empty;
		int  not;
		pcre  *re;
	}	args[2];
	enum condition_type type;
	LIST_ENTRY (condition) next;
};

struct rule {
	LIST_HEAD (condl, condition) *conditions;
	struct action *act;
	uint8_t flags;
	LIST_ENTRY (rule) next;
};

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

struct ip_list_entry {
	struct in_addr addr;
	LIST_ENTRY (ip_list_entry) next;
};

struct addr_list_entry {
	char *addr;
	size_t len;
	LIST_ENTRY (addr_list_entry) next;
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
	size_t clamav_servers_num;
	unsigned int clamav_error_time;
	unsigned int clamav_dead_time;
	unsigned int clamav_maxerrors;
	unsigned int clamav_connect_timeout;
	unsigned int clamav_port_timeout;
	unsigned int clamav_results_timeout;
	radix_compressed_t *clamav_whitelist;

	unsigned int tempfiles_mode;

	struct spamd_server spamd_servers[MAX_SPAMD_SERVERS];
	size_t spamd_servers_num;
	struct spamd_server extra_spamd_servers[MAX_SPAMD_SERVERS];
	size_t extra_spamd_servers_num;
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
	u_char spamd_soft_fail;
	u_char spamd_greylist;
	char *trace_symbol;
	char *trace_addr;
	char *spam_header;
	char *spam_header_value;
	char *spam_bar_char;
	char *spamd_settings_id;
	u_char spam_no_auth_header;
	u_char extended_spam_headers;
	unsigned int spamd_retry_timeout;
	unsigned int spamd_retry_count;
	u_char spamd_temp_fail;
	u_char spamd_never_reject;

	pcre* special_mid_re;

	bool use_redis;

	struct cache_server memcached_servers_limits[MAX_MEMCACHED_SERVERS];
	size_t memcached_servers_limits_num;
	struct cache_server memcached_servers_grey[MAX_MEMCACHED_SERVERS];
	size_t memcached_servers_grey_num;
	struct cache_server memcached_servers_white[MAX_MEMCACHED_SERVERS];
	size_t memcached_servers_white_num;
	struct cache_server memcached_servers_id[MAX_MEMCACHED_SERVERS];
	size_t memcached_servers_id_num;
	unsigned int memcached_error_time;
	unsigned int memcached_dead_time;
	unsigned int memcached_maxerrors;
	unsigned int memcached_connect_timeout;
	char *memcached_password;
	char *memcached_dbname;

	struct beanstalk_server beanstalk_servers[MAX_BEANSTALK_SERVERS];
	size_t beanstalk_servers_num;
	struct beanstalk_server *copy_server;
	struct beanstalk_server *spam_server;
	double beanstalk_copy_prob;
	char send_beanstalk_copy;
	char send_beanstalk_spam;
	char send_beanstalk_headers;
	char send_beanstalk_extra_diff;

	unsigned int beanstalk_error_time;
	unsigned int beanstalk_dead_time;
	unsigned int beanstalk_maxerrors;
	unsigned int beanstalk_connect_timeout;
	unsigned int beanstalk_lifetime;

	LIST_HEAD (ruleset, rule) rules;

	char use_dcc;
	char strict_auth;
	char weighted_clamav;

	/* limits section */
	bucket_t limit_to;
	bucket_t limit_to_ip;
	bucket_t limit_to_ip_from;
	bucket_t limit_bounce_to;
	bucket_t limit_bounce_to_ip;

	struct whitelisted_rcpt_entry *wlist_rcpt_limit;
	struct whitelisted_rcpt_entry *wlist_rcpt_global;
	LIST_HEAD (bounceaddrset, addr_list_entry) bounce_addrs;

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
	/* Autowhitelist section */
	u_char awl_enable;
	awl_hash_t *awl_hash;
	uint16_t awl_max_hits;
	unsigned int awl_ttl;
	size_t awl_pool_size;

	/* DKIM section */
	struct dkim_domain_entry *dkim_domains;
	u_char dkim_relaxed_header;
	u_char dkim_relaxed_body;
	u_char dkim_sign_sha256;
	u_char dkim_auth_only;
	u_char dkim_fold_header;
	radix_compressed_t *dkim_ip_tree;
#ifdef WITH_DKIM
	DKIM_LIB *dkim_lib;
	struct dkim_hash_entry *headers;
#endif

	/* Number of config reloads */
	short int serial;
};

int add_memcached_server (struct config_file *cf, char *str, char *str2, int type);
int add_clamav_server (struct config_file *cf, char *str);
int add_spamd_server (struct config_file *cf, char *str, int is_extra);
int add_beanstalk_server (struct config_file *cf, char *str, int is_copy);
struct action * create_action (enum action_type type, const char *message);
struct condition * create_cond (enum condition_type type, const char *arg1, const char *arg2);
void init_defaults (struct config_file *cfg);
void free_config (struct config_file *cfg);
int add_ip_radix (radix_compressed_t *tree, char *ipnet);
void add_rcpt_whitelist (struct config_file *cfg, const char *rcpt, int is_global);
int is_whitelisted_rcpt (struct config_file *cfg, const char *str, int is_global);
char *trim_quotes (char *in);

int yylex (void);
int yyparse (void);
void yyrestart (FILE *);

void parse_err (const char *fmt, ...);
void parse_warn (const char *fmt, ...);

#endif /* ifdef CFG_FILE_H */
/*
 * vi:ts=4
 */
