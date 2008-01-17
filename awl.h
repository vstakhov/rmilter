#ifndef AWL_H
#define AWL_H

#include <sys/types.h>
#ifdef _THREAD_SAFE
#include <pthread.h>
#endif

#define NEST_NUMBER 2048 / sizeof (uintptr_t)

typedef struct awl_item_s {
	uint32_t ip;
	time_t last;
	uint16_t hits;
	struct awl_item_s *prev;
	struct awl_item_s *next;
} awl_item_t;

typedef struct awl_hash_s {
	awl_item_t * nests[NEST_NUMBER];
	u_char *pool;
	size_t poolsize;
	size_t free[NEST_NUMBER];
	/* Number of hits to whitelist */
	int white_hits;
	/* Live time of record */
	int ttl;
#ifdef _THREAD_SAFE
	pthread_mutex_t locks[NEST_NUMBER];
#endif
} awl_hash_t;

awl_hash_t * awl_init (size_t poolsize, int hits, int ttl);
int awl_check (uint32_t ip, awl_hash_t *hash, time_t tm);

#endif
/*
 * vi:ts=4
 */
