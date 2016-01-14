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
#include "upstream.h"
#include "fasthash.h"

#ifdef WITH_DEBUG
#define msg_debug(args...) syslog(LOG_DEBUG, ##args)
#else
#define msg_debug(args...) do {} while(0)
#endif

#ifdef _THREAD_SAFE
pthread_rwlock_t upstream_mtx = PTHREAD_RWLOCK_INITIALIZER;
#define U_RLOCK() do { pthread_rwlock_rdlock (&upstream_mtx); } while (0)
#define U_WLOCK() do { pthread_rwlock_wrlock (&upstream_mtx); } while (0)
#define U_UNLOCK() do { pthread_rwlock_unlock (&upstream_mtx); } while (0)
#else
#define U_RLOCK() do {} while (0)
#define U_WLOCK() do {} while (0)
#define U_UNLOCK() do {} while (0)
#endif

#define MAX_TRIES 20

/*
 * Check upstream parameters and mark it whether valid or dead
 */
static void check_upstream(struct upstream *up, time_t now,
		time_t error_timeout, time_t revive_timeout, unsigned int max_errors)
{
	if (up->dead) {
		if (now - up->time >= revive_timeout) {
			msg_debug("check_upstream: reviving upstream after %ld seconds",
					(long int ) now - up->time);
			U_WLOCK ();
			up->dead = 0;
			up->errors = 0;
			up->time = 0;
			up->weight = up->priority;
			U_UNLOCK ();
		}
	}
	else {
		if (now - up->time >= error_timeout && up->errors >= max_errors) {
			msg_debug(
					"check_upstream: marking upstreams as dead after %ld errors",
					(long int ) up->errors);
			U_WLOCK ();
			up->dead = 1;
			up->time = now;
			up->weight = 0;
			U_UNLOCK ();
		}
	}
}

/* 
 * Call this function after failed upstream request
 */
void upstream_fail(struct upstream *up, time_t now)
{
	if (up->time != 0) {
		up->errors++;
	}
	else {
		U_WLOCK ();
		up->time = now;
		up->errors++;
		U_UNLOCK ();
	}
}
/* 
 * Call this function after successful upstream request
 */
void upstream_ok(struct upstream *up, time_t now)
{
	if (up->errors != 0) {
		U_WLOCK ();
		up->errors = 0;
		up->time = 0;
		U_UNLOCK ();
	}

	up->weight--;
}
/* 
 * Mark all upstreams as active. This function is used when all upstreams are marked as inactive
 */
void revive_all_upstreams(void *ups, unsigned int members, unsigned int msize)
{
	unsigned int i;
	struct upstream *cur;
	u_char *p;

	U_WLOCK ();
	msg_debug("revive_all_upstreams: starting reviving all upstreams");
	p = ups;
	for (i = 0; i < members; i++) {
		cur = (struct upstream *) p;
		cur->time = 0;
		cur->errors = 0;
		cur->dead = 0;
		cur->weight = cur->priority;
		p += msize;
	}
	U_UNLOCK ();
}

/* 
 * Scan all upstreams for errors and mark upstreams dead or alive depends on conditions,
 * return number of alive upstreams 
 */
static int rescan_upstreams(void *ups, unsigned int members, unsigned int msize,
		time_t now, time_t error_timeout, time_t revive_timeout,
		unsigned int max_errors)
{
	unsigned int i, alive;
	struct upstream *cur;
	u_char *p;

	/* Recheck all upstreams */
	p = ups;
	alive = members;
	for (i = 0; i < members; i++) {
		cur = (struct upstream *) p;
		check_upstream (cur, now, error_timeout, revive_timeout, max_errors);
		alive--;
		p += msize;
	}

	/* All upstreams are dead */
	if (alive == 0) {
		revive_all_upstreams (ups, members, msize);
		alive = members;
	}

	msg_debug("rescan_upstreams: %d upstreams alive", alive);

	return (int) alive;

}

/* Return alive upstream by its number */
static struct upstream *
get_upstream_by_number(void *ups, unsigned int members, unsigned int msize,
		int selected)
{
	int i;
	u_char *p, *c;
	struct upstream *cur;

	i = 0;
	p = ups;
	c = ups;
	U_RLOCK ();
	for (;;) {
		/* Out of range, return NULL */
		if (p > c + members * msize) {
			break;
		}

		cur = (struct upstream *) p;
		p += msize;

		if (cur->dead) {
			/* Skip inactive upstreams */
			continue;
		}
		/* Return selected upstream */
		if (i == selected) {
			U_UNLOCK ();
			return cur;
		}
		i++;
	}
	U_UNLOCK ();

	/* Error */
	return NULL;

}

/*
 * Get hash key for specified key (perl hash)
 */
static uint64_t get_hash_for_key(const unsigned char *key, unsigned int keylen)
{
	return fasthash64 (key, keylen, 0xdeadbabe);
}

/*
 * Recheck all upstreams and return random active upstream
 */
struct upstream *
get_random_upstream(void *ups, unsigned int members, unsigned int msize,
		time_t now, time_t error_timeout, time_t revive_timeout,
		unsigned int max_errors)
{
	int alive, selected;

	alive = rescan_upstreams (ups, members, msize, now, error_timeout,
			revive_timeout, max_errors);
	selected = rand () % alive;
	msg_debug("get_random_upstream: return upstream with number %d of %d",
			selected, alive);

	return get_upstream_by_number (ups, members, msize, selected);
}

/*
 * The key idea of this function is obtained from the following paper:
 * A Fast, Minimal Memory, Consistent Hash Algorithm
 * John Lamping, Eric Veach
 *
 * http://arxiv.org/abs/1406.2294
 */
static uint32_t rmilter_consistent_hash(uint64_t key, uint32_t nbuckets)
{
	int64_t b = -1, j = 0;

	while (j < nbuckets) {
		b = j;
		key *= 2862933555777941757ULL + 1;
		j = (b + 1) * (double) (1ULL << 31) / (double) ((key >> 33) + 1ULL);
	}

	return b;
}

/*
 * Return upstream by hash, that is calculated from active upstreams number
 */
struct upstream *
get_upstream_by_hash(void *ups, unsigned int members, unsigned int msize,
		time_t now, time_t error_timeout, time_t revive_timeout,
		unsigned int max_errors, const unsigned char *key, unsigned int keylen)
{
	int alive, i = 0, sel;
	uint64_t h = 0;
	char numbuf[4];
	u_char *c, *p;
	struct upstream *cur = NULL;

	alive = rescan_upstreams (ups, members, msize, now, error_timeout,
			revive_timeout, max_errors);

	if (alive == 0) {
		return NULL;
	}

	h = get_hash_for_key (key, keylen);
	sel = rmilter_consistent_hash (h, alive);

	msg_debug("get_upstream_by_hash: try to select upstream number %d of %d",
			sel, alive);
	U_RLOCK ();
	p = ups;
	c = ups;

	for (;;) {
		/* Out of range, return NULL */
		if (p > c + members * msize) {
			break;
		}

		cur = (struct upstream *) p;
		p += msize;

		if (cur->dead) {
			/* Skip inactive upstreams */
			continue;
		}
		/* Return selected upstream */
		if (i == sel) {
			U_UNLOCK ();
			return cur;
		}
		i++;
	}
	U_UNLOCK ();

	return cur;
}

/*
 * Recheck all upstreams and return upstream in round-robin order according to weight and priority
 */
struct upstream *
get_upstream_round_robin(void *ups, unsigned int members, unsigned int msize,
		time_t now, time_t error_timeout, time_t revive_timeout,
		unsigned int max_errors)
{
	unsigned int max_weight, i;
	struct upstream *cur, *selected = NULL;
	u_char *p;

	/* Recheck all upstreams */
	rescan_upstreams (ups, members, msize, now, error_timeout, revive_timeout,
			max_errors);

	p = ups;
	max_weight = 0;
	selected = (struct upstream *) p;
	U_RLOCK ();
	for (i = 0; i < members; i++) {
		cur = (struct upstream *) p;
		if (!cur->dead) {
			if ((int) max_weight < cur->weight) {
				max_weight = cur->weight;
				selected = cur;
			}
		}
		p += msize;
	}
	U_UNLOCK ();

	if (max_weight == 0) {
		p = ups;
		U_WLOCK ();
		for (i = 0; i < members; i++) {
			cur = (struct upstream *) p;
			cur->weight = cur->priority;
			if (!cur->dead) {
				if (max_weight < cur->priority) {
					max_weight = cur->priority;
					selected = cur;
				}
			}
			p += msize;
		}
		U_UNLOCK ();
	}
	msg_debug("get_upstream_round_robin: selecting upstream with weight %d",
			max_weight);

	return selected;
}

/*
 * Recheck all upstreams and return upstream in round-robin order according to only priority (master-slaves)
 */
struct upstream *
get_upstream_master_slave(void *ups, unsigned int members, unsigned int msize,
		time_t now, time_t error_timeout, time_t revive_timeout,
		unsigned int max_errors)
{
	unsigned int max_weight, i;
	struct upstream *cur, *selected = NULL;
	u_char *p;

	/* Recheck all upstreams */
	rescan_upstreams (ups, members, msize, now, error_timeout, revive_timeout,
			max_errors);

	p = ups;
	max_weight = 0;
	selected = (struct upstream *) p;
	U_RLOCK ();
	for (i = 0; i < members; i++) {
		cur = (struct upstream *) p;
		if (!cur->dead) {
			if (max_weight < cur->priority) {
				max_weight = cur->priority;
				selected = cur;
			}
		}
		p += msize;
	}
	U_UNLOCK ();
	msg_debug("get_upstream_master_slave: selecting upstream with priority %d",
			max_weight);

	return selected;
}

#undef U_LOCK
#undef U_UNLOCK
