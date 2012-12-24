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

#ifndef AWL_H
#define AWL_H

#include <sys/types.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

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
void awl_add (uint32_t ip, awl_hash_t *hash, time_t tm);

#endif
/*
 * vi:ts=4
 */
