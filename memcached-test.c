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
