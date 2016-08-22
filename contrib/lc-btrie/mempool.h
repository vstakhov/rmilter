/* memory pool #include file
 */

#ifndef _MEMPOOL_H_INCLUDED
#define _MEMPOOL_H_INCLUDED

struct mempool_chunk;

struct mempool { /* free-once memory pool.  All members are private */
  struct mempool_chunk *mp_chunk; /* list of chunks with free space */
  struct mempool_chunk *mp_fullc; /* list of full chunks */
  unsigned mp_nallocs;		/* number of allocs so far */
  unsigned mp_datasz;		/* size of allocated data */
  const char *mp_lastbuf;	/* last allocated string */
  unsigned mp_lastlen;		/* length of lastbuf */
};

void mp_init(struct mempool *mp);
void *mp_alloc(struct mempool *mp, unsigned size, int align);
void mp_free(struct mempool *mp);

#endif
