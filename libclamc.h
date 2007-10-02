/* $Id: libclamc.h,v 1.2 2006/02/21 13:47:21 mdounin Exp $ */

#ifndef LIBCLAMC_H
#define LIBCLAMC_H 1

struct config_file;

int clamscan(const char *file, const struct config_file *cfg, char *strres, size_t strres_len);

#endif
