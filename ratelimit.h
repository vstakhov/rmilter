#ifndef RATELIMIT_H
#define RATELIMIT_H
#include <sys/types.h>

/* Forward declarations */
struct mlfi_priv;
struct config_file;

int rate_check (struct mlfi_priv *priv, struct config_file *cfg, int is_update);

#endif
