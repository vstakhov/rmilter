/* Copyright (c) 2013, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <rmilter.h>
#include "config.h"
#include "radix.h"
#include "upstream.h"
#include "memcached.h"
#include "greylist.h"
#include "blake2.h"
#include "rmilter.h"
#include "utlist.h"
#include <assert.h>

static inline void
copy_alive (struct memcached_server *srv, const memcached_ctx_t mctx[2])
{
	srv->alive[0] = mctx[0].alive;
	srv->alive[1] = mctx[1].alive;
}

static void
make_greylisting_key (char *key, size_t keylen, char *prefix, const u_char *hash)
{
	size_t s, prefix_len;
	char *encoded_hash, *c;

	encoded_hash = rmilter_encode_base64 (hash, BLAKE2B_OUTBYTES, 0, &s);

	assert (encoded_hash != NULL);

	c = key;

	if (prefix) {
		prefix_len = rmilter_strlcpy (c, prefix, keylen);
		c += prefix_len;
		keylen -= prefix_len;
	}

	rmilter_strlcpy (c, encoded_hash, keylen);
	free (encoded_hash);
}

static int
greylisting_sort_rcpt_func (struct rcpt *r1, struct rcpt *r2)
{
	return strcmp (r1->r_addr, r2->r_addr);
}

static int
query_memcached_servers (struct config_file *cfg, struct memcached_server *srv,
		struct timeval *conn_tv, memcached_param_t *param)
{
	memcached_ctx_t mctx[2];
	char ipout[INET6_ADDRSTRLEN + 1];
	size_t s = 1;
	int r;

	mctx[0].protocol = cfg->memcached_protocol;
	memcpy (&mctx[0].addr, &srv->addr[0], sizeof (struct in_addr));
	mctx[0].port = srv->port[0];
	mctx[0].timeout = cfg->memcached_connect_timeout;
	mctx[0].alive = srv->alive[0];
	if (srv->num == 2) {
		mctx[1].protocol = cfg->memcached_protocol;
		memcpy (&mctx[1].addr, &srv->addr[1], sizeof (struct in_addr));
		mctx[1].port = srv->port[1];
		mctx[1].timeout = cfg->memcached_connect_timeout;
		mctx[1].alive = srv->alive[0];
	}
	else {
		mctx[1].alive = 0;
	}
	/* Reviving upstreams if all are dead */
	if (mctx[0].alive == 0 && mctx[1].alive == 0) {
		mctx[0].alive = 1;
		mctx[1].alive = 1;
		copy_alive (srv, mctx);
	}
#ifdef WITH_DEBUG
	mctx[0].options = MEMC_OPT_DEBUG;
	mctx[1].options = MEMC_OPT_DEBUG;
#else
	mctx[0].options = 0;
	mctx[1].options = 0;
#endif

	r = memc_init_ctx_mirror (mctx, 2);
	copy_alive (srv, mctx);
	if (r == -1) {
		msg_warn ("query_memcached_servers: cannot connect to memcached upstream: %s",
				inet_ntop (AF_INET, &srv->addr[0], ipout, sizeof (ipout)));
		upstream_fail (&srv->up, conn_tv->tv_sec);
		return -1;
	}
	else {
		r = memc_get_mirror (mctx, 2, param, &s);
		copy_alive (srv, mctx);
		if (r == OK) {
			memc_close_ctx_mirror (mctx, 2);
			upstream_ok (&srv->up, conn_tv->tv_sec);
			return 1;
		}
		else if (r == NOT_EXISTS) {
			memc_close_ctx_mirror (mctx, 2);
			upstream_ok (&srv->up, conn_tv->tv_sec);
			return 0;
		}
		upstream_fail (&srv->up, conn_tv->tv_sec);
		memc_close_ctx_mirror (mctx, 2);
	}

	return -1;
}

static int
push_memcached_servers (struct config_file *cfg,
		struct memcached_server *srv, struct timeval *conn_tv,
		memcached_param_t *param, time_t expire)
{
	memcached_ctx_t mctx[2];
	char ipout[INET6_ADDRSTRLEN + 1];
	size_t s = 1;
	int r;

	mctx[0].protocol = cfg->memcached_protocol;
	memcpy (&mctx[0].addr, &srv->addr[0], sizeof(struct in_addr));
	mctx[0].port = srv->port[0];
	mctx[0].timeout = cfg->memcached_connect_timeout;
	mctx[0].alive = srv->alive[0];
	if (srv->num == 2) {
		mctx[1].protocol = cfg->memcached_protocol;
		memcpy (&mctx[1].addr, &srv->addr[1], sizeof(struct in_addr));
		mctx[1].port = srv->port[1];
		mctx[1].timeout = cfg->memcached_connect_timeout;
		mctx[1].alive = srv->alive[0];
	}
	else {
		mctx[1].alive = 0;
	}
	/* Reviving upstreams if all are dead */
	if (mctx[0].alive == 0 && mctx[1].alive == 0) {
		mctx[0].alive = 1;
		mctx[1].alive = 1;
		copy_alive (srv, mctx);
	}
#ifdef WITH_DEBUG
	mctx[0].options = MEMC_OPT_DEBUG;
	mctx[1].options = MEMC_OPT_DEBUG;
#else
	mctx[0].options = 0;
	mctx[1].options = 0;
#endif

	r = memc_init_ctx_mirror (mctx, 2);
	copy_alive (srv, mctx);
	if (r == -1) {
		msg_warn("push_memcached_servers: cannot connect to memcached upstream: %s",
				inet_ntop (AF_INET, &srv->addr[0], ipout, sizeof (ipout)));
		upstream_fail (&srv->up, conn_tv->tv_sec);
		return -1;
	}
	else {
		r = memc_set_mirror (mctx, 2, param, &s, expire);
		copy_alive (srv, mctx);
		if (r == OK) {
			memc_close_ctx_mirror (mctx, 2);
			upstream_ok (&srv->up, conn_tv->tv_sec);
			return 1;
		}
		else {
			msg_err ("push_memcached_servers: cannot write to memcached(%s): %s",
					inet_ntop (AF_INET, &srv->addr[0], ipout, sizeof (ipout)),
					memc_strerror (r));
			upstream_fail (&srv->up, conn_tv->tv_sec);
			memc_close_ctx_mirror (mctx, 2);
		}
	}

	return -1;
}

static int
greylisting_check_hash (struct config_file *cfg, struct mlfi_priv *priv,
		const u_char *blake_hash, bool *exists)
{
	struct memcached_server *srv;
	memcached_param_t cur_param;
	struct timeval tm, tm1;
	int r;
	void *addr;

	addr = priv->priv_addr.family == AF_INET6
		   ? (void *) &priv->priv_addr.addr.sa6.sin6_addr :
		   (void *) &priv->priv_addr.addr.sa4.sin_addr;

	bzero (&cur_param, sizeof (cur_param));

	tm.tv_sec = priv->conn_tm.tv_sec;
	tm.tv_usec = priv->conn_tm.tv_usec;

	make_greylisting_key (cur_param.key,
			sizeof (cur_param.key),
			cfg->white_prefix,
			blake_hash);

	cur_param.buf = (u_char *) &tm1;
	cur_param.bufsize = sizeof (tm1);

	/* Check whitelist memcached */
	srv = (struct memcached_server *) get_upstream_by_hash ((void *) cfg->memcached_servers_white,
			cfg->memcached_servers_white_num,
			sizeof (struct memcached_server),
			(time_t) tm.tv_sec,
			cfg->memcached_error_time,
			cfg->memcached_dead_time,
			cfg->memcached_maxerrors,
			(char *) blake_hash,
			BLAKE2B_OUTBYTES);
	if (srv == NULL) {
		if (cfg->memcached_servers_white_num != 0) {
			msg_err ("check_greylisting: cannot get memcached upstream");
		}
	}
	else {
		if (query_memcached_servers (cfg, srv, &priv->conn_tm, &cur_param) ==
				1) {
			return GREY_WHITELISTED;
		}
	}

	/* Try to get record from memcached_grey */
	make_greylisting_key (cur_param.key,
			sizeof (cur_param.key),
			cfg->grey_prefix,
			blake_hash);
	srv = (struct memcached_server *) get_upstream_by_hash ((void *) cfg->memcached_servers_grey,
			cfg->memcached_servers_grey_num,
			sizeof (struct memcached_server),
			(time_t) tm.tv_sec,
			cfg->memcached_error_time,
			cfg->memcached_dead_time,
			cfg->memcached_maxerrors,
			(char *) blake_hash,
			BLAKE2B_OUTBYTES);
	if (srv == NULL) {
		msg_err ("check_greylisting: cannot get memcached upstream");
		return GREY_ERROR;
	}

	r = query_memcached_servers (cfg, srv, &priv->conn_tm, &cur_param);

	/* Greylisting record does not exist, writing new one */
	if (r == 0) {
		/* Write record to memcached */
		cur_param.buf = (u_char *) &tm;
		cur_param.bufsize = sizeof (tm);
		r = push_memcached_servers (cfg, srv,
				&priv->conn_tm, &cur_param, cfg->greylisting_expire);
		if (r == 1) {
			return GREY_GREYLISTED;
		}
		else {
			msg_err ("check_greylisting: cannot write to memcached: %s",
					memc_strerror (r));
		}
		*exists = false;
	}
		/* Greylisting record exists, checking time */
	else if (r == 1) {
		*exists = true;

		if ((unsigned int) tm.tv_sec - tm1.tv_sec < cfg->greylisting_timeout) {
			/* Client comes too early */
			return GREY_GREYLISTED;
		}
		else {
			/* Write to autowhitelist */
			if (cfg->awl_enable && priv->priv_addr.family == AF_INET) {
				awl_add (*(uint32_t *) addr, cfg->awl_hash,
						priv->conn_tm.tv_sec);
			}
			/* Write to whitelist memcached server */
			srv = (struct memcached_server *) get_upstream_by_hash ((void *) cfg->memcached_servers_white,
					cfg->memcached_servers_white_num,
					sizeof (struct memcached_server),
					(time_t) tm.tv_sec,
					cfg->memcached_error_time,
					cfg->memcached_dead_time,
					cfg->memcached_maxerrors,
					(char *) blake_hash,
					BLAKE2B_OUTBYTES);
			if (srv == NULL) {
				if (cfg->memcached_servers_white_num != 0) {
					msg_warn (
							"check_greylisting: cannot get memcached upstream for whitelisting");
				}
			}
			else {
				make_greylisting_key (cur_param.key,
						sizeof (cur_param.key),
						cfg->white_prefix,
						blake_hash);
				cur_param.buf = (u_char *) &tm;
				cur_param.bufsize = sizeof (tm);
				r = push_memcached_servers (cfg, srv,
						&priv->conn_tm, &cur_param, cfg->whitelisting_expire);
				if (r != 1) {
					msg_err ("check_greylisting: cannot write to memcached(%s)",
							inet_ntoa (srv->addr[0]));
				}
			}
		}
	}

	return GREY_WHITELISTED;
}

int
check_greylisting (struct config_file *cfg, struct mlfi_priv *priv)
{
	blake2b_state mdctx;
	u_char final[BLAKE2B_OUTBYTES];
	char ip_ptr[16];
	struct rcpt *rcpt;
	const char *from;
	void *addr, *map;
	struct stat st;
	unsigned long map_len;
	const long max_map_len = 10 * 1024;
	bool exists = false;
	int ret = GREY_ERROR, fd;

	/* First of all, check if we have some body */
	if (priv->eoh_pos > 0 && stat (priv->file, &st) != -1) {
		fd = open (priv->file, O_RDONLY);

		if (fd == -1) {
			msg_warn ("check_greylisting: %s: data file open(): %s",
					priv->mlfi_id, strerror (errno));
		}
		else {
			map_len = st.st_size - priv->eoh_pos;
			if (map_len > max_map_len) {
				map_len = max_map_len;
			}

			if ((map = mmap (NULL,
					map_len,
					PROT_READ,
					MAP_SHARED,
					fd,
					priv->eoh_pos)) == MAP_FAILED) {
				msg_err ("check_greylisting: %s: cannot mmap file %s: %s",
						priv->mlfi_id,
						priv->file,
						strerror (errno));
				close (fd);
			}
			else {
				close (fd);
				blake2b_init (&mdctx, BLAKE2B_OUTBYTES);
				blake2b_update (&mdctx, (const u_char *) map, map_len);
				blake2b_final (&mdctx, final, BLAKE2B_OUTBYTES);
				munmap (map, map_len);

				ret = greylisting_check_hash (cfg, priv, final, &exists);
			}
		}
	}

	if (ret == GREY_GREYLISTED && exists) {
		return ret;
	}

	/* Try also to set envelope hash */

	if (priv->priv_from[0] == '\0') {
		from = "<>";
	}
	else {
		from = priv->priv_from;
	}

	addr = priv->priv_addr.family == AF_INET6
		  ? (void *) &priv->priv_addr.addr.sa6.sin6_addr :
		  (void *) &priv->priv_addr.addr.sa4.sin_addr;

	if (priv->priv_addr.family == AF_INET) {
		if (radix32tree_find (cfg->grey_whitelist_tree,
				ntohl(*(uint32_t *)addr)) != RADIX_NO_VALUE) {
			return GREY_WHITELISTED;
		}
	}

	/* Check whitelist */
	if (cfg->awl_enable && priv->priv_addr.family == AF_INET &&
			awl_check (*(uint32_t *)addr, cfg->awl_hash, priv->conn_tm.tv_sec) ==
					1) {
		/* Auto whitelisted */
		return GREY_WHITELISTED;
	}

	memset (ip_ptr, 0, sizeof (ip_ptr));

	if (priv->priv_addr.family == AF_INET) {
		/* Mask with /19 */
		uint32_t ip = *(uint32_t *)addr;
		ip &= 0x7FFFF;
		memcpy (ip_ptr, &ip, sizeof (ip));

	}
	else {
		/* Use only network part of 64 bits */
		memcpy (ip_ptr, (char *)addr, 8);
	}


	blake2b_init (&mdctx, BLAKE2B_OUTBYTES);
	/* Make hash from components: envfrom, ip address, envrcpt */
	blake2b_update (&mdctx, (const u_char *)from, strlen(from));
	blake2b_update (&mdctx, (const u_char *)ip_ptr, sizeof(ip_ptr));

	/* Sort recipients to preserve order */
	DL_SORT ((priv->rcpts), greylisting_sort_rcpt_func);

	DL_FOREACH (priv->rcpts, rcpt) {
		blake2b_update (&mdctx, (const u_char *) rcpt->r_addr, strlen (rcpt->r_addr));
	}

	blake2b_final (&mdctx, final, BLAKE2B_OUTBYTES);

	ret = greylisting_check_hash (cfg, priv, final, &exists);

	return ret;
}
