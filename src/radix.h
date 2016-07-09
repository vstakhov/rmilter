/*
 * Copyright (c) 2009-2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
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

#ifndef RADIX_H
#define RADIX_H

#include "config.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include "util.h"

#define RADIX_NO_VALUE   (uintptr_t)-1


typedef struct radix_tree_compressed radix_compressed_t;

/**
 * Insert new key to the radix trie
 * @param tree radix trie
 * @param key key to insert (bitstring)
 * @param keylen length of the key (in bytes)
 * @param masklen lenght of mask that should be applied to the key (in bits)
 * @param value opaque value pointer
 * @return previous value of the key or `RADIX_NO_VALUE`
 */
uintptr_t
radix_insert_compressed (radix_compressed_t * tree,
	uint8_t *key, size_t keylen,
	size_t masklen,
	uintptr_t value);

/**
 * Find a key in a radix trie
 * @param tree radix trie
 * @param key key to find (bitstring)
 * @param keylen length of a key
 * @return opaque pointer or `RADIX_NO_VALUE` if no value has been found
 */
uintptr_t radix_find_compressed (radix_compressed_t * tree, const uint8_t *key,
		size_t keylen);

uintptr_t radix_find_rmilter_addr (radix_compressed_t * tree,
		const struct rmilter_inet_address *addr);

/**
 * Destroy the complete radix trie
 * @param tree
 */
void radix_destroy_compressed (radix_compressed_t *tree);

/**
 * Create new radix trie
 * @return
 */
radix_compressed_t *radix_create_compressed (void);

/**
 * Insert list of ip addresses and masks to the radix tree
 * @param list string line of addresses
 * @param separators string of characters used as separators
 * @param tree target tree
 * @return number of elements inserted
 */
int rspamd_radix_add_iplist (const char *list, const char *separators,
		radix_compressed_t *tree);

/**
 * Generic version of @see rspamd_radix_add_iplist. This function creates tree
 * if `tree` is NULL.
 */
bool radix_add_generic_iplist (const char *ip_list,
		radix_compressed_t **tree);

/**
 * Returns number of elements in the tree
 * @param tree
 * @return
 */
size_t radix_get_size (radix_compressed_t *tree);

#endif
