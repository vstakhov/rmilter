/* $Id$ */

#ifndef LIBSPAMD_H
#define LIBSPAMD_H 1
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <libmilter/mfapi.h>


struct config_file;
struct mlfi_priv;

int spamdscan(SMFICTX *ctx, struct mlfi_priv *priv, struct config_file *cfg, double spam_mark[2], char **symbols);

#endif
