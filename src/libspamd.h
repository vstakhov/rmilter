/*
 * Copyright (c) 2007-2012, Vsevolod Stakhov
 * All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer. Redistributions in binary form
 * must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with
 * the distribution. Neither the name of the author nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.

 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef LIBSPAMD_H
#define LIBSPAMD_H

#include "config.h"
#include "ucl.h"

struct config_file;
struct mlfi_priv;

struct rspamd_metric_result* spamdscan (void *ctx, struct mlfi_priv *priv,
		struct config_file *cfg, int is_extra);
void spamd_free_result (struct rspamd_metric_result *mres);


/* Structure for rspamd results */
enum rspamd_metric_action {
	METRIC_ACTION_NOACTION = 0,
	METRIC_ACTION_GREYLIST,
	METRIC_ACTION_ADD_HEADER,
	METRIC_ACTION_REWRITE_SUBJECT,
	METRIC_ACTION_SOFT_REJECT,
	METRIC_ACTION_REJECT
};

#define SPAM_IS_SPAM(res) ((res)->action >= METRIC_ACTION_ADD_HEADER)
#define SPAM_IS_GREYLIST(res) ((res)->action >= METRIC_ACTION_GREYLIST && (res)->action < METRIC_ACTION_SOFT_REJECT)

struct rspamd_symbol {
	const char *symbol;
	const ucl_object_t *options;
	double score;
	struct rspamd_symbol *prev, *next;
};

struct rspamd_metric_result {
	ucl_object_t *obj;
	const char *metric_name;
	const char *subject;
	const char *message;
	const char *message_id;
	double score;
	double required_score;
	double reject_score;
	enum rspamd_metric_action action;
	struct rspamd_symbol *symbols;
	struct mlfi_priv *priv;
	bool parsed;
};

#endif
