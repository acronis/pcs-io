/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCS_MR_MALLOC_H__
#define __PCS_MR_MALLOC_H__

#include "pcs_types.h"
#include "pcs_malloc.h"

/*
 * get_chunk method of pcs_msg tells the caller how to
 * interpretreturn value by setting *len to -PCS_*_BUF: */
#define PCS_PLAIN_BUF		0 /* buffer itself      */
#define PCS_SPLICE_BUF		1 /* pcs_splice_buf     */
#define PCS_MR_POOL_BUF		2 /* pcs_mr_buf	        */

/*
 * The following structure will be directly exposded to rdma-engine. In the
 * other words, rdma-engine will get read/write access to it.
 *
 * Initially, all its fields are NULL pointers. Handling a buffer first time,
 * rdma-engine detects mr_ctx == NULL and proceeds with ibv_reg_mr()
 * covering embracing buffer with a MR (Memory Region). The MR is only valid
 * for given PD (Protection Domain). Hence, rdma-engine saves <MR, PD> in
 * <mr_ctx, pd_ctx> of this structure.
 *
 * Along with mr_ctx/pd_ctx, rdma-engine sets mr_free_cb callback. It's
 * needed to release the MR. If we decide to release mr_pool, we'll call
 * this callback which, in turns, will call ibv_dereg_mr().
 *
 * All subsequent invocation of rdma-engine will observe mr_ctx != NULL.
 * So, rdma_engine may use mr_ctx as MR after sanity checking pd_ctx == PD.
 */
struct pcs_mr_ctx {
	void                    *mr_ctx;  /* will be set once, by rdma-engine */
	void                    *pd_ctx;  /* same thing as for mr_ctx */
	void (*mr_free_cb)(void *mr_ctx, void *pd_ctx); /* ask rdma-engine to release mr_ctx */
};

/* If get_chunk set copy to -2, rdma-engine must interpret buf as: */
struct pcs_mr_buf {
	char              *buf;  /* buffer visible to user */
	size_t             size; /* its size */
	struct pcs_mr_ctx *ctx;  /* points to mr_pool mrc */
};

struct malloc_item;

void *__pcs_malloc_mmap(struct malloc_item *tr, int bugon_if_failed, size_t size);
void  __pcs_free_mmap(void *block, size_t size);

#define TRACE_MR_ALLOC_(func, check, flags, ...) \
	({ \
	 const char *tr_file = __FILE__ ":" TRACE_STR(__LINE__);	\
	 static struct malloc_item *tr = NULL;				\
	 if (unlikely(!tr)) pcs_malloc_item_init_(&tr, tr_file, flags);	\
	 func (tr, check, __VA_ARGS__);			\
	})

#define TRACE_MR_ALLOC(func, check, ...) TRACE_MR_ALLOC_(func, check, 0, __VA_ARGS__)

#define pcs_malloc_mmap(size)  TRACE_MR_ALLOC(__pcs_malloc_mmap, 0, size)
#define pcs_xmalloc_mmap(size) TRACE_MR_ALLOC(__pcs_malloc_mmap, 1, size)
#define pcs_free_mmap(block, size) __pcs_free_mmap(block, size)

#ifndef PCS_ENABLE_RDMA

#define pcs_mr_xmalloc(size) pcs_xmalloc(size)
#define pcs_mr_malloc(size)  pcs_malloc(size)
#define pcs_mr_free(block)   pcs_free(block)

#define pcs_mr_malloc_mmap(size)      pcs_malloc_mmap(size)
#define pcs_mr_xmalloc_mmap(size)     pcs_xmalloc_mmap(size)
#define pcs_mr_free_mmap(block, size) pcs_free_mmap(block, size)

#else

enum {
	MR_HASH_TYPE_DEFAULT,
	MR_HASH_TYPE_MMAP,
	MR_HASH_TYPE_MAX
};

void *__pcs_mr_malloc(struct malloc_item *tr, int bugon_if_failed, size_t size, int hash_type);

#define TRACE_MR_ALLOC_IN_POOL(func, check, ...) TRACE_MR_ALLOC_(func, check, PCS_MALLOC_F_IN_POOL, __VA_ARGS__)

#define pcs_mr_malloc(size)       TRACE_MR_ALLOC_IN_POOL(__pcs_mr_malloc, 0, size, MR_HASH_TYPE_DEFAULT)
#define pcs_mr_xmalloc(size)      TRACE_MR_ALLOC_IN_POOL(__pcs_mr_malloc, 1, size, MR_HASH_TYPE_DEFAULT)
#define pcs_mr_xmalloc_mmap(size) TRACE_MR_ALLOC_IN_POOL(__pcs_mr_malloc, 1, size, MR_HASH_TYPE_MMAP)

void pcs_mr_free(void *block);

static inline void pcs_mr_free_mmap(void *block, size_t size)
{
	pcs_mr_free(block);
}

#endif // PCS_ENABLE_RDMA

/* Dump per-pool memory usage */
void pcs_mr_memdump(int loglevel);

/* One who provides get_chunk can use it to set pcs_mr_buf ctx pointer */
struct pcs_mr_ctx *pcs_mr_get_ctx(void *block);

/* rdma-engine will use this helper to get <addr, length> args for ibv_reg_mr() */
void *pcs_mrc2buf(struct pcs_mr_ctx *ctx, size_t *length);

static inline void unwind_mr_buf(void **buf, int *copy)
{
	if (*copy == -PCS_MR_POOL_BUF) {
		struct pcs_mr_buf *b = *buf;
		*buf = b->buf;
		*copy = b->size;
	}
}

#endif /* __PCS_MR_MALLOC_H__ */
