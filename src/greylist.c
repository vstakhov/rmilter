/* Copyright (c) 2013, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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

#include <rmilter.h>
#include "config.h"
#include "radix.h"
#include "upstream.h"
#include "cache.h"
#include "greylist.h"
#include "blake2.h"
#include "rmilter.h"
#include "utlist.h"
#include <assert.h>
#include <stdbool.h>


static int
make_greylisting_key (char *key, size_t keylen, char *prefix, const u_char *hash)
{
	size_t s, prefix_len = 0;
	char *encoded_hash, *c;
	int r = 0;

	encoded_hash = rmilter_encode_base64 (hash, BLAKE2B_OUTBYTES, 0, &s);

	assert (encoded_hash != NULL);

	c = key;

	if (prefix) {
		prefix_len = rmilter_strlcpy (c, prefix, keylen);
		r = prefix_len;
		c += prefix_len;
		keylen -= prefix_len;
	}

	r += rmilter_strlcpy (c, encoded_hash, keylen);
	free (encoded_hash);

	return r;
}

static int
greylisting_sort_rcpt_func (struct rcpt *r1, struct rcpt *r2)
{
	return strcmp (r1->r_addr, r2->r_addr);
}

static int
greylisting_check_hash (struct config_file *cfg, struct mlfi_priv *priv,
		const u_char *blake_hash, bool *exists)
{
	char key[MAXKEYLEN];
	int r, keylen;
	struct timeval *tm1 = NULL, tm;
	size_t dlen;
	void *addr;

	addr = priv->priv_addr.family == AF_INET6
		   ? (void *) &priv->priv_addr.addr.sa6.sin6_addr :
		   (void *) &priv->priv_addr.addr.sa4.sin_addr;

	keylen = make_greylisting_key (key,
			sizeof (key),
			cfg->white_prefix,
			blake_hash);

	dlen = sizeof (*tm1);

	if (rmilter_query_cache (cfg, RMILTER_QUERY_WHITELIST, key, keylen,
			(unsigned char **)&tm1, &dlen)) {
		return GREY_WHITELISTED;
	}

	if (tm1) {
		free (tm1);
	}

	/* Try to get record from memcached_grey */
	keylen = make_greylisting_key (key,
			sizeof (key),
			cfg->grey_prefix,
			blake_hash);

	tm1 = NULL;
	dlen = sizeof (*tm1);

	if (!rmilter_query_cache (cfg, RMILTER_QUERY_GREYLIST, key, keylen,
			(unsigned char **)&tm1, &dlen)) {
		/* Greylisting record does not exist, writing new one */
		gettimeofday (&tm, NULL);

		rmilter_set_cache (cfg, RMILTER_QUERY_GREYLIST, key, keylen,
				(unsigned char *)&tm, sizeof (tm), cfg->greylisting_expire);

		if (exists) {
			*exists = false;
		}

		return GREY_GREYLISTED;
	}
	else {
		/* Greylisting record exists, checking time */
		if (exists) {
			*exists = true;
		}

		gettimeofday (&tm, NULL);

		if ((unsigned int) tm.tv_sec - tm1->tv_sec < cfg->greylisting_timeout) {
			/* Client comes too early */
			if (tm1) {
				free (tm1);
			}
			return GREY_GREYLISTED;
		}
		else {
			if (tm1) {
				free (tm1);
			}
			/* Write to autowhitelist */
			if (cfg->awl_enable && priv->priv_addr.family == AF_INET) {
				awl_add (*(uint32_t *) addr, cfg->awl_hash,
						priv->conn_tm.tv_sec);
			}
			/* Write to whitelist memcached server */
			keylen = make_greylisting_key (key,
					sizeof (key),
					cfg->white_prefix,
					blake_hash);

			rmilter_set_cache (cfg, RMILTER_QUERY_WHITELIST, key, keylen,
							(unsigned char *)&tm, sizeof (tm),
							cfg->whitelisting_expire);
		}
	}

	return GREY_WHITELISTED;
}

int
check_greylisting (struct config_file *cfg, struct mlfi_priv *priv)
{
	blake2b_state mdctx;
	u_char final[BLAKE2B_OUTBYTES];
	char ip_ptr[16];
	struct rcpt *rcpt;
	const char *from;
	void *addr, *map;
	struct stat st;
	unsigned long map_len;
	const long max_map_len = 10 * 1024;
	bool exists = false;
	int ret = GREY_ERROR, fd;

	/* First of all, check if we have some body */
	if (priv->eoh_pos > 0 && stat (priv->file, &st) != -1) {
		fd = open (priv->file, O_RDONLY);

		if (fd == -1) {
			msg_warn ("check_greylisting: %s: data file open(): %s",
					priv->mlfi_id, strerror (errno));
		}
		else {
			map_len = st.st_size - priv->eoh_pos;
			if (map_len > max_map_len) {
				map_len = max_map_len;
			}

			assert (map_len <= st.st_size);

			if ((map = mmap (NULL,
					st.st_size,
					PROT_READ,
					MAP_SHARED,
					fd,
					0)) == MAP_FAILED) {
				msg_err ("check_greylisting: %s: cannot mmap file %s: %s",
						priv->mlfi_id,
						priv->file,
						strerror (errno));
				close (fd);
			}
			else {
				close (fd);
				blake2b_init (&mdctx, BLAKE2B_OUTBYTES);
				blake2b_update (&mdctx, ((const u_char *) map) + priv->eoh_pos,
						map_len);
				blake2b_final (&mdctx, final, BLAKE2B_OUTBYTES);
				munmap (map, st.st_size);

				ret = greylisting_check_hash (cfg, priv, final, &exists);
			}
		}
	}

	if (ret == GREY_GREYLISTED && exists) {
		return ret;
	}

	/* Try also to set envelope hash */

	if (priv->priv_from[0] == '\0') {
		from = "<>";
	}
	else {
		from = priv->priv_from;
	}

	addr = priv->priv_addr.family == AF_INET6
		  ? (void *) &priv->priv_addr.addr.sa6.sin6_addr :
		  (void *) &priv->priv_addr.addr.sa4.sin_addr;

	if (radix_find_rmilter_addr (cfg->grey_whitelist_tree,
			&priv->priv_addr) != RADIX_NO_VALUE) {
		return GREY_WHITELISTED;
	}

	/* Check whitelist */
	if (cfg->awl_enable && priv->priv_addr.family == AF_INET &&
			awl_check (*(uint32_t *)addr, cfg->awl_hash, priv->conn_tm.tv_sec) ==
					1) {
		/* Auto whitelisted */
		return GREY_WHITELISTED;
	}

	memset (ip_ptr, 0, sizeof (ip_ptr));

	if (priv->priv_addr.family == AF_INET) {
		/* Mask with /19 */
		uint32_t ip = *(uint32_t *)addr;
		ip &= 0x7FFFF;
		memcpy (ip_ptr, &ip, sizeof (ip));

	}
	else {
		/* Use only network part of 64 bits */
		memcpy (ip_ptr, (char *)addr, 8);
	}


	blake2b_init (&mdctx, BLAKE2B_OUTBYTES);
	/* Make hash from components: envfrom, ip address, envrcpt */
	blake2b_update (&mdctx, (const u_char *)from, strlen(from));
	blake2b_update (&mdctx, (const u_char *)ip_ptr, sizeof(ip_ptr));

	/* Sort recipients to preserve order */
	DL_SORT ((priv->rcpts), greylisting_sort_rcpt_func);

	DL_FOREACH (priv->rcpts, rcpt) {
		blake2b_update (&mdctx, (const u_char *) rcpt->r_addr, strlen (rcpt->r_addr));
	}

	blake2b_final (&mdctx, final, BLAKE2B_OUTBYTES);

	ret = greylisting_check_hash (cfg, priv, final, &exists);

	return ret;
}
