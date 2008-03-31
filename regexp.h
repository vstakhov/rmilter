/*
 * $Id$
 */

#ifndef REGEXP_H
#define REGEXP_H


#include <sys/types.h>
#include "rmilter.h"
#include "cfg_file.h"

enum milter_stage {
	STAGE_CONNECT = 0,
	STAGE_HELO,
	STAGE_ENVFROM,
	STAGE_ENVRCPT,
	STAGE_HEADER,
	STAGE_BODY,
};

struct rule  * regexp_check (const struct config_file *,	/* Config file */
				  const struct mlfi_priv *,					/* Current priv data */
				  enum milter_stage);						/* Current Stage */
struct action * rules_check (struct rule **);

#endif
