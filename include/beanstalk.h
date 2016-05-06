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

#ifndef BEANSTALK_H
#define BEANSTALK_H

#include "config.h"

struct mlfi_priv;

typedef enum bean_error {
	BEANSTALK_OK,
	BEANSTALK_BAD_COMMAND,
	BEANSTALK_CLIENT_ERROR,
	BEANSTALK_SERVER_ERROR,
	BEANSTALK_SERVER_TIMEOUT,
	BEANSTALK_NOT_EXISTS,
	BEANSTALK_EXISTS,
	BEANSTALK_WRONG_LENGTH,
	BEANSTALK_BURIED,
} bean_error_t;

typedef enum bean_cmd {
	BEANSTALK_CMD_PUT,
	BEANSTALK_CMD_PEEK,
	BEANSTALK_CMD_RELEASE,
	BEANSTALK_CMD_RESERVE,
	BEANSTALK_CMD_BURY,
	BEANSTALK_CMD_DELETE,
	BEANSTALK_CMD_KICK,
} beanstalk_cmd_t;

typedef enum bean_proto {
	BEANSTALK_UDP_TEXT,
	BEANSTALK_TCP_TEXT,
	BEANSTALK_UDP_BIN,
	BEANSTALK_TCP_BIN,
} bean_proto_t;

/* Port must be in network byte order */
typedef struct beanstalk_ctx_s {
	char *addr;
	uint16_t port;
	int sock;
	int timeout;
	/* Counter that is used for beanstalk operations in network byte order */
	uint16_t count;
} beanstalk_ctx_t;

typedef struct beanstalk_param_s {
	u_char *buf;
	size_t bufsize;
	size_t len;
	int id;
	int priority;
} beanstalk_param_t;

/* 
 * Initialize connection to beanstalk server:
 * addr, port and timeout fields in ctx must be filled with valid values
 * Return:
 * 0 - success
 * -1 - error (error is stored in errno)
 */
int bean_init_ctx (beanstalk_ctx_t *ctx, struct mlfi_priv *priv);
/*
 *    put with delay               release with delay
 * ----------------> [DELAYED] <------------.
 *                       |                   |
 *                       | (time passes)     |
 *                       |                   |
 *  put                  v     reserve       |       delete
 * -----------------> [READY] ---------> [RESERVED] --------> *poof*
 *                      ^  ^                |  |
 *                      |   \  release      |  |
 *                      |    `-------------'   |
 *                      |                      |
 *                      | kick                 |
 *                      |                      |
 *                      |       bury           |
 *                   [BURIED] <---------------'
 *                      |
 *                      |  delete
 *                       `--------> *poof*
 */
#define bean_put(ctx, params, nelem, ttr, delay) bean_write(ctx, BEANSTALK_CMD_PUT, params, nelem, ttr, delay)
#define bean_reserve(ctx, params, nelem, wait) bean_read(ctx, BEANSTALK_CMD_RESERVE, params, nelem, wait)
#define bean_peek(ctx, params, nelem, wait) bean_read(ctx, BEANSTALK_CMD_PEEK, params, nelem, wait)
#define bean_release(ctx, params, nelem, delay) bean_delete(ctx, BEANSTALK_CMD_RELEASE, params, nelem, delay)
#define bean_bury(ctx, params, nelem) bean_del(ctx, BEANSTALK_CMD_BURY, params, nelem, 0)
#define bean_kick(ctx, params, nelem) bean_del(ctx, BEANSTALK_CMD_KICK, params, nelem, 0)
#define bean_delete(ctx, params, nelem) bean_del(ctx, BEANSTALK_CMD_DELETE, params, nelem, 0)

bean_error_t bean_read (beanstalk_ctx_t *ctx, beanstalk_cmd_t cmd, beanstalk_param_t *params, size_t *nelem, u_int wait);
bean_error_t bean_write (beanstalk_ctx_t *ctx, beanstalk_cmd_t cmd, beanstalk_param_t *params, size_t *nelem, u_int ttr, u_int delay);
bean_error_t bean_del (beanstalk_ctx_t *ctx, beanstalk_cmd_t cmd, beanstalk_param_t *params, size_t nelem, u_int delay);

/* Return symbolic name of beanstalk error*/
const char * bean_strerror (bean_error_t err);

/* Destroy socket from ctx */
int bean_close_ctx (beanstalk_ctx_t *ctx);

#endif

/* 
 * vi:ts=4 
 */
