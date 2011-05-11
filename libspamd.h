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
#ifndef OWN_QUEUE_H
#include <sys/queue.h>
#else
#include "queue.h"
#endif


struct config_file;
struct mlfi_priv;

int spamdscan(SMFICTX *ctx, struct mlfi_priv *priv, struct config_file *cfg, char **subject);

/* Structure for rspamd results */
enum rspamd_metric_action {
	METRIC_ACTION_NOACTION = 0,
	METRIC_ACTION_GREYLIST,
	METRIC_ACTION_ADD_HEADER,
	METRIC_ACTION_REWRITE_SUBJECT,
	METRIC_ACTION_REJECT
};

struct rspamd_symbol {
	char *symbol;
	double score;
	TAILQ_ENTRY(rspamd_symbol) entry;
};

struct rspamd_metric_result {
	char *metric_name;
	double score;
	double required_score;
	double reject_score;
	enum rspamd_metric_action action;
	char *subject;
	TAILQ_HEAD (symbolq, rspamd_symbol) symbols;
	TAILQ_ENTRY (rspamd_metric_result) entry;
};

typedef TAILQ_HEAD(metricsq, rspamd_metric_result) rspamd_result_t;

#endif
