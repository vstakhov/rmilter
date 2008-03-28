/* $Id$ */

#ifndef LIBSPAMD_H
#define LIBSPAMD_H 1


struct config_file;

int spamdscan(const char *file, struct config_file *cfg, int spam_mark[2]);

#endif
