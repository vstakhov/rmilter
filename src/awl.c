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

#include "config.h"

#ifdef _THREAD_SAFE
#define A_LOCK(num, hash) do { pthread_mutex_lock (&(hash)->locks[(num)]); } while (0)
#define A_UNLOCK(num, hash) do { pthread_mutex_unlock (&(hash)->locks[(num)]); } while (0)
#else
#define A_LOCK(num, hash) do {} while (0)
#define A_UNLOCK(num, hash) do {} while (0)
#endif

#include "awl.h"
#include "rmilter.h"

static void *
awl_pool_alloc (int nest, size_t offset, awl_hash_t *hash)
{
	if (nest < 0 || nest > NEST_NUMBER - 1) {
		return NULL;
	}
	/* Handle nest overflow */
	if (hash->free[nest] < offset + sizeof (awl_item_t )) {
		return NULL;
	}

	hash->free[nest] -= sizeof (awl_item_t);
	return hash->pool + nest * (hash->poolsize / NEST_NUMBER) + offset;
}

static uint32_t
awl_get_hash (uint32_t a)
{
	a = (a+0x7ed55d16) + (a<<12);
	a = (a^0xc761c23c) ^ (a>>19);
	a = (a+0x165667b1) + (a<<5);
	a = (a+0xd3a2646c) ^ (a<<9);
	a = (a+0xfd7046c5) + (a<<3);
	a = (a^0xb55a4f09) ^ (a>>16);

	return a % NEST_NUMBER;
}

awl_hash_t *
awl_init (size_t poolsize, int hits, int ttl)
{
	awl_hash_t *result;
	int i;

	/* Check whether we have enough pool for operations */
	if (poolsize < sizeof (awl_item_t) * NEST_NUMBER) {
		return NULL;
	}

	result = malloc (sizeof (awl_hash_t));

	if (result == NULL) {
		return NULL;
	}
	bzero (result, sizeof (awl_hash_t));

	madvise (result->pool, poolsize, MADV_SEQUENTIAL);
	result->pool = malloc (poolsize);
	if (result->pool == NULL) {
		free (result);
		return NULL;
	}
	bzero (result->pool, poolsize);
	result->poolsize = poolsize;

	for (i = 0; i < NEST_NUMBER; i++) {
		result->free[i] = poolsize / NEST_NUMBER;
#ifdef _THREAD_SAFE
		/* result->locks[i] = PTHREAD_MUTEX_INITIALIZER; */
#endif
	}
	result->white_hits = hits;
	result->ttl = ttl;

	return result;
}

int
awl_check (uint32_t ip, awl_hash_t *hash, time_t tm)
{
	uint32_t nest;
	awl_item_t *cur;
	struct in_addr in = {.s_addr = ip};

	nest = awl_get_hash (ip);

	cur = hash->nests[nest];

	A_LOCK (nest, hash);
	while (cur) {
		/* Found record */
		if (cur->ip == ip) {
			cur->last = tm;
			msg_debug ("awl_check: ip %s in awl, hits %d", inet_ntoa (in), cur->hits);
			A_UNLOCK (nest, hash);
			if (cur->hits >= hash->white_hits) {
				/* Address whitelisted */
				msg_info ("awl_check: ip %s is whitelisted, hits %d", inet_ntoa (in), cur->hits);
				return cur->hits;
			}
			else {
				cur->hits ++;
				return 0;
			}
		}

		cur = cur->next;
	}
	A_UNLOCK (nest, hash);

	return 0;
}

void
awl_add (uint32_t ip, awl_hash_t *hash, time_t tm)
{
	uint32_t nest;
	awl_item_t *cur, *expired = NULL, *eldest = NULL, *new;
	int live_time = 0;
	struct in_addr in = {.s_addr = ip};

	nest = awl_get_hash (ip);
	/* Find free nest */
	if (hash->nests[nest] == NULL) {
		cur = awl_pool_alloc (nest, 0, hash);
		msg_info ("awl_add: insert ip %s in cache, insert first item", inet_ntoa (in));
		cur->ip = ip;
		cur->hits = 1;
		cur->last = tm;
		cur->prev = NULL;
		cur->next = NULL;
		hash->nests[nest] = cur;
		return;
	}

	cur = hash->nests[nest];

	A_LOCK (nest, hash);
	while (cur) {
		/* Find eldest item */
		if (tm - cur->last > live_time) {
			live_time = tm - cur->last;
			eldest = cur;
		}
		/* Mark expired items */
		if (tm - cur->last > hash->ttl) {
			cur->hits = 0;
			expired = cur;
		}
		if (cur->ip == ip) {
			/* Increase hits for specified item */
			A_UNLOCK (nest, hash);
			cur->last = tm;
			return;
		}
		cur = cur->next;
	}


	/* Record not found */
	if (expired != NULL) {
		/* Insert in place of expired item */
		msg_info ("awl_add: insert ip %s in cache, replace expired item", inet_ntoa (in));
		expired->ip = ip;
		expired->hits = 1;
		expired->last = tm;
	}
	if (hash->free[nest] >= sizeof (awl_item_t)) {
		/* We have enough free space in pool */
		msg_info ("awl_add: insert ip %s in cache, normal insert", inet_ntoa (in));
		new = awl_pool_alloc (nest, cur - hash->nests[nest] + sizeof (awl_item_t), hash);
		if (new == NULL) {
			A_UNLOCK (nest, hash);
			return;
		}
		new->prev = cur;
		cur->next = new;
		new->next = NULL;
		new->ip = ip;
		new->hits = 1;
		new->last = tm;
	}
	else {
		/* Not enough space in pool, replace latest used item */
		msg_info ("awl_add: insert ip %s in cache, replace eldest item", inet_ntoa (in));
		eldest->ip = ip;
		eldest->hits = 1;
		eldest->last = tm;
	}

	A_UNLOCK (nest, hash);
}

/*
 * vi:ts=4
 */
