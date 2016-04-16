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

int spamdscan (void *ctx, struct mlfi_priv *priv, struct config_file *cfg, char
		**subject, int is_extra);

/* Structure for rspamd results */
enum rspamd_metric_action {
	METRIC_ACTION_NOACTION = 0,
	METRIC_ACTION_GREYLIST,
	METRIC_ACTION_ADD_HEADER,
	METRIC_ACTION_REWRITE_SUBJECT,
	METRIC_ACTION_REJECT
};

struct rspamd_symbol {
	const char *symbol;
	const ucl_object_t *options;
	double score;
	TAILQ_ENTRY(rspamd_symbol) entry;
};

struct rspamd_metric_result {
	ucl_object_t *obj;
	const char *metric_name;
	const char *subject;
	double score;
	double required_score;
	double reject_score;
	enum rspamd_metric_action action;
	TAILQ_HEAD (symbolq, rspamd_symbol) symbols;
};

#endif
