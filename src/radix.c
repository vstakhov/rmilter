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


#include "config.h"
#include "radix.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <utlist.h>
#include <assert.h>

#define msg_debug_radix(...) do { } while(0)

struct radix_compressed_node {
	union {
		struct {
			struct radix_compressed_node *right;
			struct radix_compressed_node *left;
		} n;
		struct {
			uint8_t *key;
			unsigned int keylen;
			unsigned int level;
		} s;
	} d;
	uintptr_t value;
	bool skipped;
};

struct mem_chunk {
	void *ptr;
	struct mem_chunk *next;
};

struct radix_tree_compressed {
	struct radix_compressed_node *root;
	struct mem_chunk *chunks;
	size_t size;
};

#ifdef __GNUC__
static void * radix_alloc (struct radix_tree_compressed *tree, size_t size)
		__attribute__((malloc));
#else
static void * radix_alloc (struct radix_tree_compressed *tree, size_t size);
#endif

static void *
radix_alloc (struct radix_tree_compressed *tree, size_t size)
{
	struct mem_chunk *chunk;

	chunk = malloc (sizeof (*chunk) + size);

	if (chunk == NULL) {
		abort ();
	}

	chunk->next = NULL;
	chunk->ptr = ((uint8_t *)chunk) + sizeof (*chunk);
	LL_PREPEND (tree->chunks, chunk);

	return chunk->ptr;
}

static bool
radix_compare_compressed (struct radix_compressed_node *node,
		const uint8_t *key, unsigned int keylen, unsigned int cur_level)
{
	const uint8_t *nk;
	const uint8_t *k;
	uint8_t bit;
	unsigned int shift, rbits, skip;

	if (node->d.s.keylen > keylen) {
		/* Obvious case */
		return false;
	}


	/* Compare byte aligned levels of a compressed node */
	shift = node->d.s.level / NBBY;
	/*
	 * We know that at least of cur_level bits are the same,
	 * se we can optimize search slightly
	 */
	if (shift > 0) {
		skip = cur_level / NBBY;
		if (shift > skip &&
				memcmp (node->d.s.key + skip, key + skip, shift - skip) != 0) {
			return false;
		}
	}

	rbits = node->d.s.level % NBBY;
	if (rbits > 0) {
		/* Precisely compare remaining bits */
		nk = node->d.s.key + shift;
		k = key + shift;

		bit = 1U << 7;

		while (rbits > 0) {
			if ((*nk & bit) != (*k & bit)) {
				return false;
			}
			bit >>= 1;
			rbits --;
		}
	}

	return true;
}

uintptr_t
radix_find_compressed (radix_compressed_t * tree, const uint8_t *key, size_t keylen)
{
	struct radix_compressed_node *node;
	uint32_t bit;
	size_t kremain = keylen / sizeof (uint32_t);
	uintptr_t value;
	const uint32_t *k = (uint32_t *)key;
	uint32_t kv = ntohl (*k);
	unsigned int cur_level = 0;

	bit = 1U << 31;
	value = RADIX_NO_VALUE;
	node = tree->root;

	msg_debug_radix ("trying to find key: %*xs", (int)keylen, key);
	while (node && kremain) {
		if (node->skipped) {
			msg_debug_radix ("finding in the compressed node: %p at level %d",
					(void *)node->value, cur_level);
			/* It is obviously a leaf node */
			if (radix_compare_compressed (node, key, keylen, cur_level)) {
				return node->value;
			}
			else {
				return value;
			}
		}
		if (node->value != RADIX_NO_VALUE) {
			value = node->value;
		}

		msg_debug_radix ("finding value cur value: %p, left: %p, "
				"right: %p, go %s, level: %d",
				(void *)node->value, node->d.n.left,
				node->d.n.right, (kv & bit) ? "right" : "left",
				cur_level);
		if (kv & bit) {
			node = node->d.n.right;
		}
		else {
			node = node->d.n.left;
		}

		bit >>= 1;
		if (bit == 0) {
			k ++;
			bit = 1U << 31;
			kv = ntohl (*k);
			kremain --;
		}
		cur_level ++;
	}

	if (node) {
		/* We still have a node but no more key, so we can search for skipped node */
		if (node->skipped) {
			msg_debug_radix ("finding in the compressed node: %p at level %d",
					(void *)node->value, cur_level);
			/* It is obviously a leaf node */
			if (radix_compare_compressed (node, key, keylen, cur_level)) {
				return node->value;
			}
		}
	}

	return value;
}

uintptr_t
radix_find_rmilter_addr (radix_compressed_t * tree,
		const struct rmilter_inet_address *addr)
{
	const uint8_t *key;
	size_t keylen;

	switch (addr->family) {
	case AF_INET:
		key = (const uint8_t *)&addr->addr.sa4.sin_addr;
		keylen = sizeof (addr->addr.sa4.sin_addr);
		break;
	case AF_INET6:
		key = (const uint8_t *)&addr->addr.sa6.sin6_addr;
		keylen = sizeof (addr->addr.sa6.sin6_addr);
		break;
	default:
		return RADIX_NO_VALUE;
	}

	return radix_find_compressed (tree, key, keylen);
}

static struct radix_compressed_node *
radix_uncompress_path (radix_compressed_t *tree,
		struct radix_compressed_node *node,
		unsigned int start_level,
		unsigned int levels_uncompress)
{
	uint8_t *nkey = node->d.s.key + start_level / NBBY;
	uint8_t bit = 1U << (7 - start_level % NBBY);
	struct radix_compressed_node *leaf, *next;

	/* Make compressed leaf */
	leaf = radix_alloc (tree, sizeof (*node));
	memcpy (leaf, node, sizeof (*node));

	/* Make compressed node as uncompressed */
	node->skipped = false;
	node->value = RADIX_NO_VALUE;

	msg_debug_radix (
			"uncompress %ud levels of tree from %ud to %ud, stored key: %*xs",
			levels_uncompress,
			start_level,
			start_level + levels_uncompress,
			leaf->d.s.keylen,
			leaf->d.s.key);

	/* Uncompress the desired path */
	while (levels_uncompress) {
		next = radix_alloc (tree, sizeof (*node));

		next->skipped = false;
		next->value = RADIX_NO_VALUE;

		if (*nkey & bit) {
			node->d.n.right = next;
			node->d.n.left = NULL;
		}
		else {
			node->d.n.left = next;
			node->d.n.right = NULL;
		}

		msg_debug_radix ("uncompress path for node: %p, left: %p, "
				"right: %p, go %s", (void *)node->value, node->d.n.left,
				node->d.n.right, (*nkey & bit) ? "right" : "left");

		bit >>= 1;
		if (bit == 0) {
			nkey ++;
			bit = 1U << 7;
		}
		node = next;
		levels_uncompress --;
	}

	/* Attach leaf node, that was previously a compressed node */
	msg_debug_radix ("attach leaf node to %s with value %p", (*nkey & bit) ? "right" : "left",
			(void *)leaf->value);
	if (*nkey & bit) {
		node->d.n.right = leaf;
		node->d.n.left = NULL;
	}
	else {
		node->d.n.left = leaf;
		node->d.n.right = NULL;
	}

	/* Return node */
	return node;
}


static struct radix_compressed_node *
radix_make_leaf_node (radix_compressed_t *tree,
		uint8_t *key, unsigned int keylen, unsigned int level,
		uintptr_t value,
		bool compressed)
{
	struct radix_compressed_node *node;

	node = radix_alloc (tree, sizeof (struct radix_compressed_node));
	if (compressed) {
		node->skipped = true;
		node->d.s.keylen = keylen;
		node->d.s.key = radix_alloc (tree, node->d.s.keylen);
		node->d.s.level = level;
		memcpy (node->d.s.key, key, node->d.s.keylen);
	}
	else {
		/* Uncompressed leaf node */
		memset (node, 0, sizeof (*node));
	}
	node->value = value;
	msg_debug_radix ("insert new leaf node with value %p to level %d",
			(void *)value, level);

	return node;
}

static void
radix_move_up_compressed_leaf (radix_compressed_t *tree,
		struct radix_compressed_node *leaf,
		struct radix_compressed_node *parent, uintptr_t value,
		uint8_t *key, unsigned int keylen, unsigned int leaf_level)
{
	parent->value = leaf->value;

	leaf->value = value;
	leaf->d.s.keylen = keylen;
	leaf->d.s.key = radix_alloc (tree, leaf->d.s.keylen);
	memcpy (leaf->d.s.key, key, keylen);
	leaf->d.s.level = leaf_level;
}

static uintptr_t
radix_replace_node (radix_compressed_t *tree,
		struct radix_compressed_node *node,
		uint8_t *key, size_t keylen,
		uintptr_t value)
{
	uintptr_t oldval;

	if (node->skipped) {
		/*
		 * For leaf nodes we have to deal with the keys as well, since
		 * we might find that keys are different for the same leaf node
		 */
		node->d.s.keylen = keylen;
		node->d.s.key = radix_alloc (tree, node->d.s.keylen);
		memcpy (node->d.s.key, key, node->d.s.keylen);
		oldval = node->value;
		node->value = value;
		msg_debug_radix ("replace value for leaf node with: %p, old value: %p",
				(void *)value, (void *)oldval);
	}
	else {
		oldval = node->value;
		node->value = value;
		msg_debug_radix ("replace value for node with: %p, old value: %p",
				(void *)value, (void *)oldval);
	}

	return oldval;
}

static uintptr_t
radix_uncompress_node (radix_compressed_t *tree,
		struct radix_compressed_node *node,
		uint8_t *key, size_t keylen,
		uintptr_t value,
		unsigned int cur_level,
		unsigned int target_level,
		uint8_t bit)
{
	/* Find the largest common prefix of the compressed node and target node */
	size_t kremain = keylen - cur_level / NBBY;
	uint8_t *nkey = node->d.s.key + cur_level / NBBY;
	uint8_t *k = key + cur_level / NBBY;
	unsigned int levels_uncompress = 0, start_level = cur_level;
	bool masked = false;
	struct radix_compressed_node *leaf;

	msg_debug_radix ("want to uncompress nodes from level %ud to level %ud, "
			"compressed node level: %ud",
			cur_level, target_level, node->d.s.level);
	while (cur_level < target_level) {
		uint8_t kb = *k & bit;
		uint8_t nb = *nkey & bit;

		if (cur_level >= node->d.s.level) {
			msg_debug_radix ("found available masked path at level %ud", cur_level);
			masked = true;
			break;
		}
		if (kb != nb) {
			msg_debug_radix ("found available path at level %ud", cur_level);
			break;
		}

		cur_level ++;
		levels_uncompress ++;
		bit >>= 1;
		if (bit == 0) {
			k ++;
			nkey ++;
			bit = 1U << 7;
			kremain --;
		}
	}

	if (kremain == 0) {
		/* Nodes are equal */
		return radix_replace_node (tree, node, key, keylen, value);
	}
	else {
		/*
		 * We need to uncompress the common path
		 */
		struct radix_compressed_node *nnode;

		nnode = radix_uncompress_path (tree, node, start_level, levels_uncompress);

		/*
		 * Now nnode is the last uncompressed node with compressed leaf inside
		 * and we also know that the current bit is different
		 *
		 * - if we have target_level == cur_level, then we can safely assign the
		 * value of that parent node
		 * - otherwise we insert new compressed leaf node
		 */
		if (cur_level == target_level) {
			msg_debug_radix ("insert detached leaf node with value: %p",
					(void *)value);
			nnode->value = value;
		}
		else if (masked) {
			/*
			 * Here we just add the previous value of node to the current node
			 * and replace value in the leaf
			 */
			if (nnode->d.n.left != NULL) {
				leaf = nnode->d.n.left;
			}
			else {
				leaf = nnode->d.n.right;
			}
			msg_debug_radix ("move leaf node with value: %p, to level %ud, "
					"set leaf node value to %p and level %ud", (void *)nnode->value,
					cur_level,
					(void *)value, target_level);
			radix_move_up_compressed_leaf (tree, leaf, nnode, value, key, keylen,
					target_level);
		}
		else {
			node = radix_make_leaf_node (tree, key, keylen,
					target_level, value, true);
			if (nnode->d.n.left == NULL) {
				nnode->d.n.left = node;
			}
			else {
				nnode->d.n.right = node;
			}
		}
		tree->size ++;
	}

	return value;
}


uintptr_t
radix_insert_compressed (radix_compressed_t * tree,
	uint8_t *key, size_t keylen,
	size_t masklen,
	uintptr_t value)
{
	struct radix_compressed_node *node, *next = NULL, **prev;
	size_t keybits = keylen * NBBY;
	unsigned int target_level = (keylen * NBBY - masklen);
	unsigned int cur_level = 0;
	uint8_t bit, *k = key;
	size_t kremain = keylen;
	uintptr_t oldval = RADIX_NO_VALUE;

	bit = 1U << 7;
	node = tree->root;

	assert (keybits >= masklen);
	msg_debug_radix ("want insert value %p with mask %z, key: %*xs",
			(void *)value, masklen, (int)keylen, key);

	node = tree->root;
	next = node;
	prev = &tree->root;

	/* Search for the place to insert element */
	while (node && cur_level < target_level) {
		if (node->skipped) {
			/* We have found skipped node and we need to uncompress it */
			return radix_uncompress_node (tree, node, key, keylen, value,
					cur_level, target_level, bit);
		}
		if (*k & bit) {
			next = node->d.n.right;
			prev = &node->d.n.right;
		}
		else {
			next = node->d.n.left;
			prev = &node->d.n.left;
		}

		if (next == NULL) {
			/* Need to insert some nodes */
			break;
		}

		bit >>= 1;
		if (bit == 0) {
			k ++;
			bit = 1U << 7;
			kremain --;
		}
		cur_level ++;
		node = next;
	}

	if (next == NULL) {
		next = radix_make_leaf_node (tree, key, keylen, target_level, value,
				true);
		*prev = next;
		tree->size ++;
	}
	else if (next->value == RADIX_NO_VALUE) {
		msg_debug_radix ("insert value node with %p", (void *)value);
		next->value = value;
		tree->size ++;
	}
	else {
		if (next->skipped) {
			/*
			 * For skipped node we replace value if the level of skipped node
			 * is equal to the target level
			 */
			if (next->d.s.level == target_level) {
				oldval = radix_replace_node (tree, next, key, keylen, value);
			}
			else if (next->d.s.level > target_level) {
				/*
				 * Here we must create new normal node and insert compressed leaf
				 * one level below
				 */
				node = radix_make_leaf_node (tree, key, keylen,
						target_level, value, false);
				*prev = node;
				if (*k & bit) {
					node->d.n.right = next;
				}
				else {
					node->d.n.left = next;
				}
				oldval = next->value;
				tree->size ++;
			}
			else {
				/*
				 * We must convert old compressed node to a normal node and
				 * create new compressed leaf attached to that normal node
				 */
				node = radix_make_leaf_node (tree, key, keylen,
						target_level, value, true);
				*prev = next;
				msg_debug_radix ("move leaf node with value: %p, to level %ud, "
						"set leaf node value to %p and level %ud", (void *)next->value,
						cur_level,
						(void *)value, target_level);
				next->skipped = false;
				if (*k & bit) {
					next->d.n.right = node;
					next->d.n.left = NULL;
				}
				else {
					next->d.n.left = node;
					next->d.n.right = NULL;
				}
				oldval = next->value;
				tree->size ++;
			}
		}
		else {
			oldval = radix_replace_node (tree, next, key, keylen, value);
		}
		return oldval;
	}

	return next->value;
}


radix_compressed_t *
radix_create_compressed (void)
{
	radix_compressed_t *tree;

	tree = calloc (1, sizeof (*tree));
	if (tree == NULL) {
		return NULL;
	}

	tree->size = 0;
	tree->root = NULL;

	return tree;
}

void
radix_destroy_compressed (radix_compressed_t *tree)
{
	struct mem_chunk *chunk, *tmp;

	if (tree) {
		LL_FOREACH_SAFE (tree->chunks, chunk, tmp) {
			free (chunk);
		}
		free (tree);
	}
}

int
rspamd_radix_add_iplist (const char *list, const char *separators,
		radix_compressed_t *tree)
{
	char *token, *ipnet, *err_str, **strv, *cur, *cpy, *to_free;
	struct in_addr ina;
	struct in6_addr ina6;
	unsigned int k = INT_MAX;
	int af;
	int res = 0;

	/* Split string if there are multiple items inside a single string */
	cpy = strdup (list);
	to_free = cpy;

	while ((cur = strsep (&cpy, separators)) != NULL) {
		af = AF_UNSPEC;
		if (*cur == '\0') {
			continue;
		}

		/* Extract ipnet */
		ipnet = cur;
		token = strsep (&ipnet, "/");

		if (ipnet != NULL) {
			errno = 0;
			/* Get mask */
			k = strtoul (ipnet, &err_str, 10);
			if (errno != 0) {
				msg_debug_radix (
						"invalid netmask, error detected on symbol: %s, erorr: %s",
						err_str,
						strerror (errno));
				k = INT_MAX;
			}
		}

		/* Check IP */
		if (inet_pton (AF_INET, token, &ina) == 1) {
			af = AF_INET;
		}
		else if (inet_pton (AF_INET6, token, &ina6) == 1) {
			af = AF_INET6;
		}
		else {
			msg_debug_radix ("invalid IP address: %s", token);
		}

		if (af == AF_INET) {
			if (k > 32) {
				k = 32;
			}
			radix_insert_compressed (tree, (uint8_t *)&ina, sizeof (ina),
					32 - k, 1);
			res ++;
		}
		else if (af == AF_INET6){
			if (k > 128) {
				k = 128;
			}
			radix_insert_compressed (tree, (uint8_t *)&ina6, sizeof (ina6),
					128 - k, 1);
			res ++;
		}
	}

	free (to_free);

	return res;
}

bool
radix_add_generic_iplist (const char *ip_list, radix_compressed_t **tree)
{
	if (*tree == NULL) {
		*tree = radix_create_compressed ();
	}

	return (rspamd_radix_add_iplist (ip_list, ",; ", *tree) > 0);
}


size_t
radix_get_size (radix_compressed_t *tree)
{
	if (tree != NULL) {
		return tree->size;
	}

	return 0;
}
