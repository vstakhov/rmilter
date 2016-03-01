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

#include "config.h"
#include "radix.h"
#include "upstream.h"
#include "cache.h"
#include "greylist.h"
#include "blake2.h"
#include "rmilter.h"
#include "utlist.h"
#include "mfapi.h"
#include <assert.h>
#include <stdbool.h>
#include <math.h>

#define GREYLISTING_HEADER "X-Rmilter-Greylist"

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
		const u_char *blake_hash, bool *exists,
		char *hdr_buf, size_t hdr_size, const char *type)
{
	char key[MAXKEYLEN], timebuf[64];
	int r, keylen;
	time_t elapsed;
	struct timeval *tm1 = NULL, tm;
	struct tm tm_parsed;
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
		elapsed = tm1->tv_sec + cfg->whitelisting_expire;
		localtime_r (&elapsed, &tm_parsed);
		strftime (timebuf, sizeof (timebuf), "%F %T", &tm_parsed);
		snprintf (hdr_buf, hdr_size, "Whitelisted till %s, type: %s",
				timebuf, type);

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

	if (gettimeofday (&tm, NULL) == -1) {
		msg_err ("<%s>: gettimeofday failed: %s", priv->mlfi_id,
				strerror (errno));

		return GREY_WHITELISTED;
	}

	if (!rmilter_query_cache (cfg, RMILTER_QUERY_GREYLIST, key, keylen,
			(unsigned char **)&tm1, &dlen) || (tm1 && tm1->tv_sec > tm.tv_sec)) {
		/* Greylisting record does not exist or is insane, writing new one */

		if (rmilter_set_cache (cfg, RMILTER_QUERY_GREYLIST, key, keylen,
				(unsigned char *)&tm, sizeof (tm), cfg->greylisting_expire)) {

			if (exists) {
				*exists = false;
			}

			elapsed = time (NULL) + cfg->greylisting_timeout;
			localtime_r (&elapsed, &tm_parsed);
			strftime (timebuf, sizeof (timebuf), "%F %T", &tm_parsed);
			snprintf (hdr_buf, hdr_size, "0 seconds passed (new record), "
					"greylisted till %s, type: %s",
					timebuf, type);
			msg_info ("greylisting_check_hash: greylisted <%s>: %s",
					priv->mlfi_id, hdr_buf);
			if (tm1) {
				free (tm1);
			}
		}
		else {
			msg_err ("greylisting_check_hash: cannot store greylisting data "
					"for <%s>: %s",
					priv->mlfi_id, type);
			if (tm1) {
				free (tm1);
			}

			return GREY_WHITELISTED;
		}

		return GREY_GREYLISTED;
	}
	else {
		/* Greylisting record exists, checking time */
		if (exists) {
			*exists = true;
		}

		if ((unsigned int) tm.tv_sec - tm1->tv_sec < cfg->greylisting_timeout) {
			/* Client comes too early */

			elapsed = tm1->tv_sec + cfg->greylisting_timeout;
			localtime_r (&elapsed, &tm_parsed);
			strftime (timebuf, sizeof (timebuf), "%F %T", &tm_parsed);
			snprintf (hdr_buf, hdr_size, "%d seconds passed, "
					"greylisted till %s, type: %s",
					(int)(tm.tv_sec - tm1->tv_sec),
					timebuf, type);
			msg_info ("greylisting_check_hash: greylisted <%s>: %s",
					priv->mlfi_id, hdr_buf);

			if (tm1) {
				free (tm1);
			}

			return GREY_GREYLISTED;
		}
		else {
			elapsed = tm1->tv_sec + cfg->whitelisting_expire;
			localtime_r (&elapsed, &tm_parsed);
			strftime (timebuf, sizeof (timebuf), "%F %T", &tm_parsed);
			snprintf (hdr_buf, hdr_size, "Greylisted for %d seconds, "
					"whitelisted till %s, type: %s",
					(int)(tm.tv_sec - tm1->tv_sec),
					timebuf, type);

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
check_greylisting (void *_ctx, struct config_file *cfg, struct mlfi_priv *priv)
{
	blake2b_state mdctx;
	u_char final[BLAKE2B_OUTBYTES];
	char greylist_buf[1024];
	char ip_ptr[16], ip_str[INET6_ADDRSTRLEN + 1];
	struct rcpt *rcpt;
	const char *from;
	void *addr, *map;
	struct stat st;
	unsigned long map_len;
	const long max_map_len = 10 * 1024;
	bool exists = false;
	int ret = GREY_ERROR, fd, ahits;
	SMFICTX *ctx = _ctx;

	greylist_buf[0] = 0;
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

				ret = greylisting_check_hash (cfg, priv, final, &exists,
						greylist_buf, sizeof (greylist_buf), "data hash");
			}
		}
	}

	if (exists) {
		/*
		 * If data hash exists, there is no reason to check more hashes
		 */
		goto end;
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
		memset (ip_str, 0, sizeof (ip_str));
		inet_ntop (priv->priv_addr.family, addr, ip_str, sizeof (ip_str) - 1);
		snprintf (greylist_buf, sizeof (greylist_buf),
				"Sender IP %s is whitelisted by configuration",
				ip_str);
		ret = GREY_WHITELISTED;
		goto end;
	}

	/* Check whitelist */
	if (cfg->awl_enable && priv->priv_addr.family == AF_INET) {

		ahits = awl_check (*(uint32_t *)addr, cfg->awl_hash, priv->conn_tm.tv_sec);

		if (ahits > 0) {
			/* Auto whitelisted */
			ret = GREY_WHITELISTED;
			memset (ip_str, 0, sizeof (ip_str));
			inet_ntop (priv->priv_addr.family, addr, ip_str, sizeof (ip_str) - 1);
			snprintf (greylist_buf, sizeof (greylist_buf),
					"Sender IP %s is auto-whitelisted after %d hits",
					ip_str, ahits);
			goto end;
		}
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

	ret = greylisting_check_hash (cfg, priv, final, &exists,
			greylist_buf, sizeof (greylist_buf), "sender, IP, recipients");

end:

	if (greylist_buf[0] != 0) {
		smfi_addheader (ctx, GREYLISTING_HEADER, greylist_buf);
	}

	return ret;
}
