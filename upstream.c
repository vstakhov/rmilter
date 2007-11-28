#ifdef _THREAD_SAFE
#include <pthread.h>
#endif

#include <sys/types.h>
#include <time.h>
#include <stdlib.h>
#include "upstream.h"

#ifdef _THREAD_SAFE
pthread_mutex_t upstream_mtx = PTHREAD_MUTEX_INITIALIZER;
#define U_LOCK() do { pthread_mutex_lock (&upstream_mtx); } while (0)
#define U_UNLOCK() do { pthread_mutex_unlock (&upstream_mtx); } while (0)
#else
#define U_LOCK() do {} while (0)
#define U_UNLOCK() do {} while (0)
#endif

static void
check_upstream (struct upstream *up, time_t now, time_t error_timeout, time_t revive_timeout, size_t max_errors)
{
	if (up->dead) {
		if (now - up->time >= revive_timeout) {
			U_LOCK ();
			up->dead = 0;
			up->errors = 0;
			up->time = 0;
			U_UNLOCK ();
		}
	}
	else {
		if (now - up->time >= error_timeout && up->errors >= max_errors) {
			U_LOCK ();
			up->dead = 1;
			up->time = now;
			U_UNLOCK ();
		}
	}
}

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

void
upstream_ok (struct upstream *up, time_t now)
{
	if (up->errors != 0) {
		U_LOCK ();
		up->errors = 0;
		up->time = 0;
		U_UNLOCK ();
	}
}

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
		p += msize;
	}
	U_UNLOCK ();
}

struct upstream *
get_random_upstream (void *ups, size_t members, size_t msize, time_t now, time_t error_timeout, time_t revive_timeout, size_t max_errors)
{
	int i, alive, selected;
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

	selected = rand () % alive;
	
	i = 0;
	p = ups;
	for (;;) {
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

#undef U_LOCK
#undef U_UNLOCK
/* 
 * vi:ts=4 
 */
