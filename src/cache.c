/*
 * Copyright (c) 2016, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
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

#include "config.h"
#include "memcached.h"
#include "cfg_file.h"
#include "cache.h"
#include "hiredis.h"
#include "upstream.h"
#include "util.h"
#include <assert.h>

static struct cache_server *
rmilter_get_server (struct config_file *cfg, enum rmilter_query_type type,
		const unsigned char *key, size_t keylen)
{
	struct cache_server *serv = NULL;
	void *ptr = NULL;
	unsigned mlen = 0;

	switch (type) {
	case RMILTER_QUERY_GREYLIST:
		if (cfg->memcached_servers_grey_num > 0) {
			ptr = cfg->memcached_servers_grey;
			mlen = cfg->memcached_servers_grey_num;
		}
		break;
	case RMILTER_QUERY_WHITELIST:
		if (cfg->memcached_servers_white_num > 0) {
			ptr = cfg->memcached_servers_white;
			mlen = cfg->memcached_servers_white_num;
		}
		break;
	case RMILTER_QUERY_RATELIMIT:
		if (cfg->memcached_servers_limits_num > 0) {
			ptr = cfg->memcached_servers_limits;
			mlen = cfg->memcached_servers_limits_num;
		}
		break;
	case RMILTER_QUERY_ID:
		if (cfg->memcached_servers_id_num > 0) {
			ptr = cfg->memcached_servers_id;
			mlen = cfg->memcached_servers_id_num;
		}
		break;
	}

	if (ptr) {
		serv = (struct cache_server *)get_upstream_by_hash (ptr, mlen,
				sizeof (*serv), time (NULL),
				cfg->memcached_error_time, cfg->memcached_dead_time,
				cfg->memcached_maxerrors, key, keylen);
	}

	return serv;
}

bool
rmilter_query_cache (struct config_file *cfg, enum rmilter_query_type type,
		const unsigned char *key, size_t keylen,
		unsigned char **data, size_t *datalen)
{
	struct cache_server *serv;
	redisContext *redis;
	redisReply *r;
	struct timeval tv;
	bool ret = false;
	size_t nelems = 1;
	memcached_ctx_t mctx;
	memcached_param_t memc_param;
	int rep;

	serv = rmilter_get_server (cfg, type, key, keylen);

	if (serv) {
		if (cfg->use_redis) {
			msec_to_tv (cfg->memcached_connect_timeout, &tv);
			redis = redisConnectWithTimeout (serv->addr, serv->port, tv);

			if (redis == NULL || redis->err != 0) {
				msg_err ("cannot connect to %s:%d: %s", serv->addr,
						(int)serv->port, redis ? redis->errstr : "unknown error");
			}
			else {
				r = redisCommand (redis, "GET %b", key, keylen);

				if (r != NULL) {
					if (r->type == REDIS_REPLY_STRING) {
						*data = malloc (r->len);
						if (*data) {
							memcpy (*data, r->str, r->len);
							ret = true;
							if (*datalen) {
								*datalen = r->len;
							}
						}
					}

					freeReplyObject (r);
				}
				redisFree (redis);
			}
		}
		else {
			memset (&mctx, 0, sizeof (mctx));
			mctx.addr = serv->addr;
			mctx.port = serv->port;
			mctx.protocol = TCP_TEXT;
			mctx.timeout = cfg->memcached_connect_timeout;

			assert (datalen != NULL && *datalen != 0);
			rmilter_strlcpy (memc_param.key, key, sizeof (memc_param.key));
			memc_param.buf = malloc (*datalen);
			memc_param.bufsize = *datalen;

			if (memc_init_ctx (&mctx) != 0) {
				msg_err ("cannot connect to %s:%d: %s", serv->addr,
						(int)serv->port, strerror (errno));

				return false;
			}

			rep = memc_get (&mctx, &memc_param, &nelems);

			if (rep != OK) {
				msg_err ("cannot get key on %s:%d: %s", serv->addr,
						(int)serv->port, memc_strerror (rep));
				free (memc_param.buf);
				*datalen = 0;
			}
			else {
				*data = memc_param.buf;
			}

			memc_close_ctx (&mctx);
		}
	}

	return ret;
}

bool
rmilter_set_cache (struct config_file *cfg, enum rmilter_query_type type ,
		const unsigned char *key, size_t keylen,
		const unsigned char *data, size_t datalen,
		unsigned expire)
{
	struct cache_server *serv;
	redisContext *redis;
	redisReply *r;
	struct timeval tv;
	memcached_ctx_t mctx;
	memcached_param_t memc_param;
	size_t nelems = 1;
	int rep;

	serv = rmilter_get_server (cfg, type, key, keylen);

	if (serv) {
		if (cfg->use_redis) {
			msec_to_tv (cfg->memcached_connect_timeout, &tv);
			redis = redisConnectWithTimeout (serv->addr, serv->port, tv);

			if (redis == NULL || redis->err != 0) {
				msg_err ("cannot connect to %s:%d: %s", serv->addr,
						(int)serv->port, redis ? redis->errstr : "unknown error");

				return false;
			}
			else {
				r = redisCommand (redis, "SET %b %b", key, keylen,
						data, datalen);

				if (expire > 0 && r != NULL) {
					freeReplyObject (r);
					r = redisCommand (redis, "EXPIRE %b %d", key, keylen,
							expire);

					if (r) {
						freeReplyObject (r);
					}
				}

				redisFree (redis);
			}
		}
		else {
			memset (&mctx, 0, sizeof (mctx));
			mctx.addr = serv->addr;
			mctx.port = serv->port;
			mctx.protocol = TCP_TEXT;
			mctx.timeout = cfg->memcached_connect_timeout;
			rmilter_strlcpy (memc_param.key, key, sizeof (memc_param.key));
			memc_param.buf = (void *)data;
			memc_param.bufsize = datalen;

			if (memc_init_ctx (&mctx) != 0) {
				msg_err ("cannot connect to %s:%d: %s", serv->addr,
						(int)serv->port, strerror (errno));

				return false;
			}

			rep = memc_set (&mctx, &memc_param, &nelems, expire);

			if (rep != OK) {
				msg_err ("cannot set key on %s:%d: %s", serv->addr,
						(int)serv->port, memc_strerror (rep));
			}

			memc_close_ctx (&mctx);
		}
	}

	return true;
}

bool
rmilter_delete_cache (struct config_file *cfg, enum rmilter_query_type type ,
		const unsigned char *key, size_t keylen)
{
	struct cache_server *serv;
	redisContext *redis;
	redisReply *r;
	struct timeval tv;
	memcached_ctx_t mctx;
	memcached_param_t memc_param;
	size_t nelems = 1;
	int rep;

	serv = rmilter_get_server (cfg, type, key, keylen);

	if (serv) {
		if (cfg->use_redis) {
			msec_to_tv (cfg->memcached_connect_timeout, &tv);
			redis = redisConnectWithTimeout (serv->addr, serv->port, tv);

			if (redis == NULL || redis->err != 0) {
				msg_err ("cannot connect to %s:%d: %s", serv->addr,
						(int)serv->port, redis ? redis->errstr : "unknown error");

				return false;
			}
			else {
				r = redisCommand (redis, "DELETE %b", key, keylen);

				if (r != NULL) {
					freeReplyObject (r);
				}

				redisFree (redis);
			}
		}
		else {
			memset (&mctx, 0, sizeof (mctx));
			mctx.addr = serv->addr;
			mctx.port = serv->port;
			mctx.protocol = TCP_TEXT;
			mctx.timeout = cfg->memcached_connect_timeout;
			rmilter_strlcpy (memc_param.key, key, sizeof (memc_param.key));
			memc_param.buf = NULL;
			memc_param.bufsize = 0;

			if (memc_init_ctx (&mctx) != 0) {
				msg_err ("cannot connect to %s:%d: %s", serv->addr,
						(int)serv->port, strerror (errno));

				return false;
			}

			rep = memc_delete (&mctx, &memc_param, &nelems);

			if (rep != OK) {
				msg_err ("cannot delete key on %s:%d: %s", serv->addr,
						(int)serv->port, memc_strerror (rep));
			}

			memc_close_ctx (&mctx);
		}
	}

	return true;
}
