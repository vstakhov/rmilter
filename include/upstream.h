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

#ifndef UPSTREAM_H
#define UPSTREAM_H

#include "config.h"

struct upstream {
	unsigned int errors;
	time_t time;
	unsigned char dead;
	unsigned char priority;
	int16_t weight;
};

struct mlfi_priv;

void upstream_fail (struct upstream *up, time_t now);
void upstream_ok (struct upstream *up, time_t now);
void revive_all_upstreams (void *ups, unsigned int members, unsigned int msize,
		const struct mlfi_priv *priv);

struct upstream* get_random_upstream   (void *ups, unsigned int members, unsigned int msize,
		time_t now, time_t error_timeout,
		time_t revive_timeout, unsigned int max_errors, const struct mlfi_priv *priv);

struct upstream* get_upstream_by_hash  (void *ups, unsigned int members, unsigned int msize,
		time_t now,  time_t error_timeout,
		time_t revive_timeout, unsigned int max_errors,
		const unsigned char *key, unsigned int keylen,
		const struct mlfi_priv *priv);

struct upstream* get_upstream_round_robin (void *ups, unsigned int members, unsigned int msize,
		time_t now, time_t error_timeout,
		time_t revive_timeout, unsigned int max_errors,
		const struct mlfi_priv *priv);

struct upstream* get_upstream_master_slave (void *ups, unsigned int members, unsigned int msize,
		time_t now, time_t error_timeout,
		time_t revive_timeout, unsigned int max_errors,
		const struct mlfi_priv *priv);

#endif /* UPSTREAM_H */
