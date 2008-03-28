/* $Id$ */

#ifndef LIBCLAMC_H
#define LIBCLAMC_H 1
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif


struct config_file;

int clamscan(const char *file, struct config_file *cfg, char *strres, size_t strres_len);

#endif
