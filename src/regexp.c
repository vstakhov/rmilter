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

#include "utlist.h"
#include "pcre.h"
#include "rmilter.h"
#include "cfg_file.h"
#include "regexp.h"

extern pthread_mutex_t regexp_mtx;

#define C_LOCK() do { pthread_mutex_lock (&regexp_mtx); } while (0)
#define C_UNLOCK() do { pthread_mutex_unlock (&regexp_mtx); } while (0)

static int
check_condition (struct cond_arg *arg, const char *match_str, size_t str_len)
{
	int ovector[30];
	int r;

	if (!arg || !match_str || arg->empty) {
		return 0;
	}

 	r = pcre_exec (arg->re, NULL, match_str, str_len, 0, 0, ovector, sizeof(ovector)/sizeof(int));

	if (arg->not) {
		return r < 0;
	}
	else {
		return r >= 0;
	}
}

static struct rule *
check_connect_rule (struct rule *cur, const struct mlfi_priv *priv)
{
	struct condition *cond;
	size_t hlen, iplen;

	hlen = strlen (priv->priv_hostname);
	iplen = strlen (priv->priv_ip);

	LIST_FOREACH (cond, cur->conditions, next) {
		if (cond->type == COND_CONNECT) {
			/* Hostname and ip address */
			if (check_condition (&cond->args[0], priv->priv_hostname, hlen)
			    && check_condition (&cond->args[1], priv->priv_ip, iplen)) {
				return cur;
			}
		}
	}
	return NULL;
}

static struct rule *
check_helo_rule (struct rule *cur, const struct mlfi_priv *priv)
{
	struct condition *cond;
	size_t hlen;

	hlen = strlen (priv->priv_helo);

	LIST_FOREACH (cond, cur->conditions, next) {
		if (cond->type == COND_HELO) {
			/* Helo */
			if (check_condition (&cond->args[0], priv->priv_helo, hlen)) {
				return cur;
			}
		}
	}
	return NULL;
}

static struct rule *
check_envfrom_rule (struct rule *cur, const struct mlfi_priv *priv)
{
	struct condition *cond;
	size_t flen;

	flen = strlen (priv->priv_from);

	LIST_FOREACH (cond, cur->conditions, next) {
		if (cond->type == COND_ENVFROM) {
			/* From: */
			if (check_condition (&cond->args[0], priv->priv_from, flen)) {
				return cur;
			}
		}
	}
	return NULL;
}

static struct rule *
check_envrcpt_rule (struct rule *cur, const struct mlfi_priv *priv)
{
	struct condition *cond;
	struct rcpt *rcpt;
	size_t tlen;

	LIST_FOREACH (cond, cur->conditions, next) {
		if (cond->type == COND_ENVRCPT) {
			/* To: */
			DL_FOREACH (priv->rcpts, rcpt) {
				tlen = strlen (rcpt->r_addr);
				if (check_condition (&cond->args[0], rcpt->r_addr, tlen)) {
					return cur;
				}
			}
		}
	}
	return NULL;
}
static struct rule *
check_header_rule (struct rule *cur, const struct mlfi_priv *priv)
{
	struct condition *cond;
	size_t nlen, vlen;

	nlen = strlen (priv->priv_cur_header.header_name);
	vlen = strlen (priv->priv_cur_header.header_value);

	LIST_FOREACH (cond, cur->conditions, next) {
		if (cond->type == COND_HEADER) {
			/* Header name and value */
			if (check_condition (&cond->args[0], priv->priv_cur_header.header_name, nlen)
				&& check_condition (&cond->args[1], priv->priv_cur_header.header_value, vlen)) {
				return cur;
			}
		}
	}
	return NULL;
}

static struct rule *
check_body_rule (struct rule *cur, const struct mlfi_priv *priv)
{
	struct condition *cond;

	LIST_FOREACH (cond, cur->conditions, next) {
		if (cond->type == COND_BODY) {
			/* Body line */
			if (check_condition (&cond->args[0], priv->priv_cur_body.value, priv->priv_cur_body.len)) {
				return cur;
			}
		}
	}
	return NULL;
}

struct rule *
regexp_check (const struct config_file *cfg, const struct mlfi_priv *priv, enum milter_stage stage)
{
	struct rule *cur;
	struct rule *r = NULL;

	/* Check rules for specific stage */
	LIST_FOREACH (cur, &cfg->rules, next) {
		if ((cur->flags & COND_CONNECT_FLAG) != 0 && stage == STAGE_CONNECT) {
			C_LOCK ();
			r = check_connect_rule (cur, priv);
			C_UNLOCK ();

		} else if ((cur->flags & COND_HELO_FLAG) != 0 && stage == STAGE_HELO) {
			C_LOCK ();
			r = check_helo_rule (cur, priv);
			C_UNLOCK ();

		} else if ((cur->flags & COND_ENVFROM_FLAG) != 0 && stage == STAGE_ENVFROM) {
			C_LOCK ();
			r = check_envfrom_rule (cur, priv);
			C_UNLOCK ();

		} else if ((cur->flags & COND_ENVRCPT_FLAG) != 0 && stage == STAGE_ENVRCPT) {
			C_LOCK ();
			r = check_envrcpt_rule (cur, priv);
			C_UNLOCK ();

		} else if ((cur->flags & COND_HEADER_FLAG) != 0 && stage == STAGE_HEADER) {
			C_LOCK ();
			r = check_header_rule (cur, priv);
			C_UNLOCK ();

		} else if ((cur->flags & COND_BODY_FLAG) != 0 && stage == STAGE_BODY) {
			C_LOCK ();
			r = check_body_rule (cur, priv);
			C_UNLOCK ();

		}
		/* Stop matching on finding matched rule */
		if (r != NULL) {
			return r;
		}
	}

	return NULL;
}

struct action *
rules_check (struct rule **rules)
{
	struct rule *cur = NULL;
	struct condition *cond;
	int i, r;

	for (i = 0; i < STAGE_MAX; i++) {
		if (rules[i] == NULL) {
			continue;
		}
		cur = rules[i];
		r = 1;
		LIST_FOREACH (cond, cur->conditions, next) {
			if (rules[cond->type] == 0) {
				r = 0;
				break;
			}
		}
		/* Return reject actions before any accept action */
		if (r == 1 && cur->act->type != ACTION_ACCEPT) {
			return cur->act;
		}
		else if (r == 0) {
			cur = NULL;
		}
	}

	/* Return accept action if found */
	if (cur) {
		return cur->act;
	}

	return NULL;
}

#undef C_LOCK
#undef C_UNLOCK
