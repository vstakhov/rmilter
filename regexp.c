/*
 * $Id$
 */

#include <sys/types.h>
#include <string.h>

#include "pcre.h"
#include "rmilter.h"
#include "cfg_file.h"
#include "regexp.h"

int 
regexp_check (const struct config_file *cfg, const struct mlfi_priv *priv, enum milter_stage stage, char **err_msg)
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
			*err_msg = r->message;
			return r->type;
		}
	}
	
	/* Accept by default */
	return ACTION_ACCEPT;
}
