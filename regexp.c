/*
 * $Id$
 */

#include <sys/types.h>
#include <string.h>

#include "pcre.h"
#include "rmilter.h"
#include "cfg_file.h"
#include "regexp.h"

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

static struct action *
check_connect_rule (const struct rule *cur, const struct mlfi_priv *priv)
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
				return cur->act;
			}
		}
	}
	return NULL;
}

static struct action *
check_helo_rule (const struct rule *cur, const struct mlfi_priv *priv)
{
	struct condition *cond;
	size_t hlen;

	hlen = strlen (priv->priv_helo);

	LIST_FOREACH (cond, cur->conditions, next) {
		if (cond->type == COND_HELO) {
			/* Helo */
			if (check_condition (&cond->args[0], priv->priv_helo, hlen)) {
				return cur->act;
			}
		}
	}
	return NULL;
}

static struct action *
check_envfrom_rule (const struct rule *cur, const struct mlfi_priv *priv)
{
	struct condition *cond;
	size_t flen;

	flen = strlen (priv->priv_from);

	LIST_FOREACH (cond, cur->conditions, next) {
		if (cond->type == COND_ENVFROM) {
			/* From: */
			if (check_condition (&cond->args[0], priv->priv_from, flen)) {
				return cur->act;
			}
		}
	}
	return NULL;
}

static struct action *
check_envrcpt_rule (const struct rule *cur, const struct mlfi_priv *priv)
{
	struct condition *cond;
	size_t tlen;

	tlen = strlen (priv->priv_cur_rcpt);

	LIST_FOREACH (cond, cur->conditions, next) {
		if (cond->type == COND_ENVRCPT) {
			/* To: */
			if (check_condition (&cond->args[0], priv->priv_cur_rcpt, tlen)) {
				return cur->act;
			}
		}
	}
	return NULL;
}
static struct action *
check_header_rule (const struct rule *cur, const struct mlfi_priv *priv)
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
				return cur->act;
			}
		}
	}
	return NULL;
}

static struct action *
check_body_rule (const struct rule *cur, const struct mlfi_priv *priv)
{
	struct condition *cond;

	LIST_FOREACH (cond, cur->conditions, next) {
		if (cond->type == COND_BODY) {
			/* Body line */
			if (check_condition (&cond->args[0], priv->priv_cur_body.value, priv->priv_cur_body.len)) {
				return cur->act;
			}
		}
	}
	return NULL;
}

struct action *
regexp_check (const struct config_file *cfg, const struct mlfi_priv *priv, enum milter_stage stage)
{
	struct rule *cur;
	struct action *r = NULL;

	/* Check rules for specific stage */
	LIST_FOREACH (cur, &cfg->rules, next) {
		if ((cur->flags & COND_CONNECT_FLAG) != 0 && stage == STAGE_CONNECT) {
			r = check_connect_rule (cur, priv);

		} else if ((cur->flags & COND_HELO_FLAG) != 0 && stage == STAGE_HELO) {
			r = check_helo_rule (cur, priv);

		} else if ((cur->flags & COND_ENVFROM_FLAG) != 0 && stage == STAGE_ENVFROM) {
			r = check_envfrom_rule (cur, priv);

		} else if ((cur->flags & COND_ENVRCPT_FLAG) != 0 && stage == STAGE_ENVRCPT) {
			r = check_envrcpt_rule (cur, priv);

		} else if ((cur->flags & COND_HEADER_FLAG) != 0 && stage == STAGE_HEADER) {
			r = check_header_rule (cur, priv);

		} else if ((cur->flags & COND_BODY_FLAG) != 0 && stage == STAGE_BODY) {
			r = check_body_rule (cur, priv);

		}
		/* Stop matching on finding matched rule */
		if (r != NULL) {
			return r;
		}
	}
	
	return NULL;
}

