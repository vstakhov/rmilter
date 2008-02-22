#ifdef _THREAD_SAFE
#include <pthread.h>
#endif

#include <sys/types.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include "upstream.h"


#ifdef _THREAD_SAFE
pthread_mutex_t upstream_mtx = PTHREAD_MUTEX_INITIALIZER;
#define U_LOCK() do { pthread_mutex_lock (&upstream_mtx); } while (0)
#define U_UNLOCK() do { pthread_mutex_unlock (&upstream_mtx); } while (0)
#else
#define U_LOCK() do {} while (0)
#define U_UNLOCK() do {} while (0)
#endif

/*
 * Check upstream parameters and mark it whether valid or dead
 */
static void
check_upstream (struct upstream *up, time_t now, time_t error_timeout, time_t revive_timeout, size_t max_errors)
{
	if (up->dead) {
		if (now - up->time >= revive_timeout) {
			U_LOCK ();
			up->dead = 0;
			up->errors = 0;
			up->time = 0;
			up->weight = up->priority;
			U_UNLOCK ();
		}
	}
	else {
		if (now - up->time >= error_timeout && up->errors >= max_errors) {
			U_LOCK ();
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
void
upstream_fail (struct upstream *up, time_t now)
{
	if (up->time != 0) {
		up->errors ++;
	}
	else {
		U_LOCK ();
		up->time = now;
		up->errors ++;
		U_UNLOCK ();
	}
}
/* 
 * Call this function after successfull upstream request
 */
void
upstream_ok (struct upstream *up, time_t now)
{
	if (up->errors != 0) {
		U_LOCK ();
		up->errors = 0;
		up->time = 0;
		U_UNLOCK ();
	}

	up->weight --;
}
/* 
 * Mark all upstreams as active. This function is used when all upstreams are marked as inactive
 */
void
revive_all_upstreams (void *ups, size_t members, size_t msize) 
{
	int i;
	struct upstream *cur;
	u_char *p;

	U_LOCK ();
	p = ups;
	for (i = 0; i < members; i++) {
		cur = (struct upstream *)p;
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
static int
rescan_upstreams (void *ups, size_t members, size_t msize, time_t now, time_t error_timeout, time_t revive_timeout, size_t max_errors)
{	
	int i, alive;
	struct upstream *cur;
	u_char *p;
	
	/* Recheck all upstreams */
	p = ups;
	alive = members;
	for (i = 0; i < members; i++) {
		cur = (struct upstream *)p;
		check_upstream (cur, now, error_timeout, revive_timeout, max_errors);
		alive -= cur->dead;
		p += msize;
	}
	
	/* All upstreams are dead */
	if (alive == 0) {
		revive_all_upstreams (ups, members, msize);
		alive = members;
	}
	
	return alive;

}

/* Return alive upstream by its number */
static struct upstream *
get_upstream_by_number (void *ups, size_t members, size_t msize, int selected)
{
	int i;
	u_char *p, *c;
	struct upstream *cur;

	i = 0;
	p = ups;
	c = ups;
	for (;;) {
		/* Out of range, return NULL */
		if (p > c + members * msize) {
			break;
		}

		cur = (struct upstream *)p;
		p += msize;

		if (cur->dead) {
			/* Skip inactive upstreams */
			continue;
		}
		/* Return selected upstream */
		if (i == selected) {
			return cur;
		}
		i++;
	}

	/* Error */
	return NULL;

}

/*
 * Recheck all upstreams and return random active upstream
 */
struct upstream *
get_random_upstream (void *ups, size_t members, size_t msize, time_t now, time_t error_timeout, time_t revive_timeout, size_t max_errors)
{
	int alive, selected;
	
	alive = rescan_upstreams (ups, members, msize, now, error_timeout, revive_timeout, max_errors);
	selected = rand () % alive;
	
	return get_upstream_by_number (ups, members, msize, selected); 
}

/*
 * Return upstream by hash, that is calculated from active upstreams number
 */
struct upstream *
get_upstream_by_hash (void *ups, size_t members, size_t msize, time_t now, 
						time_t error_timeout, time_t revive_timeout, size_t max_errors,
						char *key, size_t keylen)
{
	int alive;
	uint32_t h, i;
	char *p;
	
	alive = rescan_upstreams (ups, members, msize, now, error_timeout, revive_timeout, max_errors);

	i = keylen;      /* Work back through the key length */
	p = key;         /* Character pointer */
	h = 0;           /* The hash value */

	while (i--) {
		h += *p++;
		h += (h << 10);
		h ^= (h >> 6);
	}

	h += (h << 3);
	h ^= (h >> 11);
	h += (h << 15);

	if (h == 0) {
		h = 1;
	}

	h = h % alive;

	return get_upstream_by_number (ups, members, msize, h); 
}

/*
 * Recheck all upstreams and return upstream in round-robin order according to weight and priority
 */
struct upstream *
get_upstream_round_robin (void *ups, size_t members, size_t msize, time_t now, time_t error_timeout, time_t revive_timeout, size_t max_errors)
{
	int alive, max_weight, i;
	struct upstream *cur, *selected = NULL;
	u_char *p;
	
	/* Recheck all upstreams */
	alive = rescan_upstreams (ups, members, msize, now, error_timeout, revive_timeout, max_errors);

	p = ups;
	max_weight = 0;
	for (i = 0; i < members; i++) {
		cur = (struct upstream *)p;
		if (!cur->dead) {
			if (max_weight < cur->weight) {
				max_weight = cur->weight;
				selected = cur;
			}
		}
		p += msize;
	}

	if (max_weight == 0) {
		p = ups;
		for (i = 0; i < members; i++) {
			cur =  (struct upstream *)p;
			cur->weight = cur->priority;
			if (!cur->dead) {
				if (max_weight < cur->priority) {
					max_weight = cur->priority;
					selected = cur;
				}
			}
			p += msize;
		}
	}

	return selected;
}

/*
 * Recheck all upstreams and return upstream in round-robin order according to only priority (master-slaves)
 */
struct upstream *
get_upstream_master_slave (void *ups, size_t members, size_t msize, time_t now, time_t error_timeout, time_t revive_timeout, size_t max_errors)
{
	int alive, max_weight, i;
	struct upstream *cur, *selected = NULL;
	u_char *p;
	
	/* Recheck all upstreams */
	alive = rescan_upstreams (ups, members, msize, now, error_timeout, revive_timeout, max_errors);

	p = ups;
	max_weight = 0;
	for (i = 0; i < members; i++) {
		cur = (struct upstream *)p;
		if (!cur->dead) {
			if (max_weight < cur->priority) {
				max_weight = cur->priority;
				selected = cur;
			}
		}
		p += msize;
	}

	return selected;
}


#undef U_LOCK
#undef U_UNLOCK
/* 
 * vi:ts=4 
 */
