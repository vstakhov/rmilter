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


#ifndef INCLUDE_CACHE_H_
#define INCLUDE_CACHE_H_

#include "config.h"
#include <stdint.h>

#ifndef MAXKEYLEN
#define MAXKEYLEN 250
#endif

struct config_file;

enum rmilter_query_type {
	RMILTER_QUERY_GREYLIST = 0,
	RMILTER_QUERY_WHITELIST,
	RMILTER_QUERY_RATELIMIT,
	RMILTER_QUERY_ID,
};

/**
 * Query cache (preferring redis) for the specified key
 * @param cfg
 * @param type type of query
 * @param key key to check
 * @param keylen length of the key
 * @param data data returned by a server (must be freed by a caller)
 * @param datalen pointer to length of data (out)
 * @return
 */
bool rmilter_query_cache (struct config_file *cfg, enum rmilter_query_type type,
		const unsigned char *key, size_t keylen,
		unsigned char **data, size_t *datalen);

bool rmilter_set_cache (struct config_file *cfg, enum rmilter_query_type type ,
		const unsigned char *key, size_t keylen,
		const unsigned char *data, size_t datalen, unsigned expire);

bool rmilter_delete_cache (struct config_file *cfg, enum rmilter_query_type type ,
		const unsigned char *key, size_t keylen);

#endif /* INCLUDE_CACHE_H_ */
