/* $Id: libclamc.h,v 1.2 2006/02/21 13:47:21 mdounin Exp $ */

#ifndef LIBCLAMC_H
#define LIBCLAMC_H 1

int clamscan(const char *file, const char *sockets, char *strres, size_t strres_len);

#endif
