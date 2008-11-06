/*
 * $Id$
 */


#ifndef CFG_FILE_H
#define CFG_FILE_H

#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifndef OWN_QUEUE_H
#include <sys/queue.h>
#else
#include "queue.h"
#endif
#ifdef HAVE_STRLCPY_H
#include "strlcpy.h"
#endif
#include <netinet/in.h>
#include <sys/un.h>
#include <pthread.h>
#include "pcre.h"
#include "upstream.h"
#include "memcached.h"
#include "radix.h"
#include "awl.h"

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
#define DEFAULT_MEMCACHED_PORT 11211
#define DEFAULT_CLAMAV_PORT 3310
#define DEFAULT_SPAMD_PORT 783
/* Clamav timeouts */
#define DEFAULT_CLAMAV_CONNECT_TIMEOUT 1000
#define DEFAULT_CLAMAV_PORT_TIMEOUT 3000
#define DEFAULT_CLAMAV_RESULTS_TIMEOUT 20000
/* Spamd timeouts */
#define DEFAULT_SPAMD_CONNECT_TIMEOUT 1000
#define DEFAULT_SPAMD_RESULTS_TIMEOUT 20000
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

#define DEFAUL_SPAMD_REJECT "Spam message rejected; If this is not spam contact abuse at rambler-co.ru"

#define yyerror(fmt, ...) \
		fprintf (stderr, "Config file parse error!\non line: %d\n", yylineno); \
		fprintf (stderr, "while reading text: %s\nreason: ", yytext); \
		fprintf (stderr, fmt, ##__VA_ARGS__); \
		fprintf (stderr, "\n")
#define yywarn(fmt, ...) \
		fprintf (stderr, "Config file parse warning!\non line %d\n", yylineno); \
		fprintf (stderr, "while reading text: %s\nreason: ", yytext); \
		fprintf (stderr, fmt, ##__VA_ARGS__); \
		fprintf (stderr, "\n")

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
	int sock_type;

	union {
		char *unix_path;
		struct {
			struct in_addr addr;
			uint16_t port;
		} inet;
	} sock;

	char *name;
};

struct spamd_server {
	struct upstream up;
	int sock_type;

	union {
		char *unix_path;
		struct {
			struct in_addr addr;
			uint16_t port;
		} inet;
	} sock;

	char *name;
};

struct memcached_server {
	struct upstream up;
	struct in_addr addr[2];
	uint16_t port[2];
	short alive[2];
	short int num;
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

	struct spamd_server spamd_servers[MAX_SPAMD_SERVERS];
	size_t spamd_servers_num;
	unsigned int spamd_error_time;
	unsigned int spamd_dead_time;
	unsigned int spamd_maxerrors;
	unsigned int spamd_connect_timeout;
	unsigned int spamd_results_timeout;
	radix_tree_t *spamd_whitelist;
	char *spamd_reject_message;

	struct memcached_server memcached_servers_limits[MAX_MEMCACHED_SERVERS];
	size_t memcached_servers_limits_num;
	struct memcached_server memcached_servers_grey[MAX_MEMCACHED_SERVERS];
	size_t memcached_servers_grey_num;
	struct memcached_server memcached_servers_white[MAX_MEMCACHED_SERVERS];
	size_t memcached_servers_white_num;
	struct memcached_server memcached_servers_id[MAX_MEMCACHED_SERVERS];
	size_t memcached_servers_id_num;
	memc_proto_t memcached_protocol;
	unsigned int memcached_error_time;
	unsigned int memcached_dead_time;
	unsigned int memcached_maxerrors;
	unsigned int memcached_connect_timeout;

	LIST_HEAD (ruleset, rule) rules;
	
	/* Must be sorted */
	char **spf_domains;
	size_t spf_domains_num;

	char use_dcc;

	/* limits section */
	bucket_t limit_to;
	bucket_t limit_to_ip;
	bucket_t limit_to_ip_from;
	bucket_t limit_bounce_to;
	bucket_t limit_bounce_to_ip;

	LIST_HEAD (whitelistipset, ip_list_entry) whitelist_ip;
	LIST_HEAD (whitelistaddrset, addr_list_entry) whitelist_rcpt;
	LIST_HEAD (bounceaddrset, addr_list_entry) bounce_addrs;
	
	unsigned int greylisting_timeout;
	unsigned int greylisting_expire;
	unsigned int whitelisting_expire;
	char *id_prefix;
	char *grey_prefix;
	char *white_prefix;
	radix_tree_t *grey_whitelist_tree;
	/* Autowhitelist section */
	u_char awl_enable;
	awl_hash_t *awl_hash;
	uint16_t awl_max_hits;
	unsigned int awl_ttl;
	size_t awl_pool_size;

	/* Number of config reloads */
	short int serial;
};

int add_memcached_server (struct config_file *cf, char *str, char *str2, int type);
int add_clamav_server (struct config_file *cf, char *str);
int add_spamd_server (struct config_file *cf, char *str);
struct action * create_action (enum action_type type, const char *message);
struct condition * create_cond (enum condition_type type, const char *arg1, const char *arg2);
int add_spf_domain (struct config_file *cfg, char *domain);
void init_defaults (struct config_file *cfg);
void free_config (struct config_file *cfg);
int add_ip_radix (radix_tree_t *tree, char *ipnet);

int yylex (void);
int yyparse (void);
void yyrestart (FILE *);

#endif /* ifdef CFG_FILE_H */
/* 
 * vi:ts=4 
 */
