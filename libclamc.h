/* $Id$ */

#ifndef LIBCLAMC_H
#define LIBCLAMC_H 1


struct config_file;

int clamscan(const char *file, struct config_file *cfg, char *strres, size_t strres_len);

#endif
