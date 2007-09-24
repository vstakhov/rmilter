/*
 * $Id$
 */

#ifndef SPF_H
#define SPF_H

#include "cfg_file.h"

struct mlfi_priv;

int read_spf_map (struct config_file *, const char *);
int spf_check (struct mlfi_priv *);

#endif /* SPF_H */
