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

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "upstream.h"
#include "memcached.h"

#define HOST "127.0.0.1"
#define PORT 11211


int 
main (int argc, char **argv)
{
	memcached_ctx_t mctx;
	memcached_param_t cur_param;
	size_t s;
	memc_error_t r;
	char *addr, buf[512];
	
	strcpy (cur_param.key, "testkey");
	strcpy (buf, "test_value");
	cur_param.buf = buf;
	cur_param.bufsize = sizeof ("test_value") - 1;

	if (argc == 2) {
		addr = argv[1];
	}
	else {
		addr = HOST;
	}
	
	mctx.protocol = UDP_TEXT;
	mctx.timeout = 1;
	mctx.port = htons (PORT);
	inet_aton (addr, &mctx.addr);

	memc_init_ctx (&mctx);

	printf ("Setting value to memcached: %s -> %s\n", cur_param.key, (char *)cur_param.buf);
	s = 1;
	r = memc_set (&mctx, &cur_param, &s, 60);

	printf ("Result: %s\n", memc_strerror(r));
	/* Set buf to some random value to test get function */
	strcpy (buf, "lalala");

	r = memc_get (&mctx, &cur_param, &s);
	printf ("Getting value from memcached: %s -> %s\n", cur_param.key, (char *)cur_param.buf);
	printf ("Result: %s\n", memc_strerror(r));
	r = memc_delete (&mctx, &cur_param, &s);
	printf ("Deleting value from memcached: %s\n", cur_param.key);
	printf ("Result: %s\n", memc_strerror(r));

	/* Set buf to some random value to test get function */
	strcpy (buf, "lalala");
	r = memc_get (&mctx, &cur_param, &s);
	printf ("Trying to get deleted value from memcached: %s -> %s\n", cur_param.key, (char *)cur_param.buf);
	printf ("Result: %s\n", memc_strerror(r));

	memc_close_ctx (&mctx);

	return 0;
}
