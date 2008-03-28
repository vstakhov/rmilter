/* $Id$ */

#ifndef LIBSPAMD_H
#define LIBSPAMD_H 1
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif


struct config_file;

int spamdscan(const char *file, struct config_file *cfg, int spam_mark[2]);

#endif
