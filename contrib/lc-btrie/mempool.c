/* memory pool implementation
 */

#include <stdlib.h>
#include <string.h>
#include "mempool.h"

#define MEM_ALIGNMENT   16    /* Better for SSE */
#define alignmask (MEM_ALIGNMENT-1)

#define MEMPOOL_CHUNKSIZE (65536-sizeof(unsigned)*4)

struct mempool_chunk {
	char buf[MEMPOOL_CHUNKSIZE+MEM_ALIGNMENT];
	struct mempool_chunk *next;
	unsigned size;
};

struct mempool_cfull { /* pseudo-chunk: one entry into full list */
	struct mempool_chunk *next;
	char buf[1];
};

void mp_init(struct mempool *mp) {
	memset (mp, 0, sizeof (*mp));
}

void *mp_alloc(struct mempool *mp, unsigned size, int align) {
	if (size >= MEMPOOL_CHUNKSIZE / 2) {
		/* for large blocks, allocate separate "full" chunk */
		struct mempool_cfull *c = malloc (sizeof(*c)+size-1);
		if (!c) {
			return NULL;
		}
		c->next = mp->mp_fullc;
		mp->mp_fullc = (struct mempool_chunk*)c;
		return c->buf;
	}
	else {
		struct mempool_chunk *c;
		struct mempool_chunk *best; /* "best fit" chunk */
		unsigned avg; /* average data size: total size / numallocs */

		++mp->mp_nallocs; mp->mp_datasz += size;
		avg = mp->mp_datasz / mp->mp_nallocs;

		/* round size up to a multiple of alignto */
		if (align) {
			size = (size + alignmask) & ~alignmask;
		}

		for(c = mp->mp_chunk, best = NULL; c; c = c->next)
			if (c->size >= size && (!best || best->size > c->size)) {
				best = c;
				if (c->size - size < avg) {
					break;
				}
			}

		if (best != NULL) { /* found a free chunk */
			char *b;
			if (align) {
				best->size &= ~alignmask;
			}

			b = best->buf + MEMPOOL_CHUNKSIZE - best->size;
			best->size -= size;

			if (best->size < avg) {
				struct mempool_chunk **cp = &mp->mp_chunk;
				while(*cp != best) {
					cp = &(*cp)->next;
				}
				*cp = best->next;
				best->next = mp->mp_fullc;
				mp->mp_fullc = best;
			}
			return b;
		}

		else { /* no sutable chunks -> allocate new one */
			c = (struct mempool_chunk *)malloc(sizeof(*c));
			if (!c) {
				return NULL;
			}

			c->next = mp->mp_chunk;
			mp->mp_chunk = c;
			c->size = MEMPOOL_CHUNKSIZE - size;

			return c->buf;
		}
	}
}

void mp_free(struct mempool *mp) {
	struct mempool_chunk *c;

	while((c = mp->mp_chunk) != NULL) {
		mp->mp_chunk = c->next;
		free(c);
	}

	while((c = mp->mp_fullc) != NULL) {
		mp->mp_fullc = c->next;
		free(c);
	}
}
