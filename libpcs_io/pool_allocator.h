/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#pragma once

/* This is the almost zero overhead pool allocator best suited for small objects.
 * Objects larger than some fraction of the page size would be better served by
 * standard malloc. The allocator initialization function just returns -1 for
 * such object sizes.
 *
 * The allocator consists of 2 parts - the central pool of pages and the
 * allocator specialized on allocating objects of the particular size.
 *
 * The allocator does not care about thread safety. It must be ensured
 * externally if necessary.
 */

#include "std_list.h"

/* Define to enforce page faults on accessing freed chunks */
//#define MEM_POOL_GUARD

/* Define for testing */
//#define MEM_POOL_DEBUG

#ifdef MEM_POOL_GUARD
#define MEM_POOL_DEBUG
#endif

/* How many pages will be allocated at once */
#ifdef MEM_POOL_DEBUG
#define MEM_POOL_PREALLOC_PGS 0x1
#else
#define MEM_POOL_PREALLOC_PGS 0x100
#endif

/* The allocation alignment */
#define MEM_POOL_ALLOC_ALIGN sizeof(void*)

/* The minimum number of allocations per page.
 * Note that below some threshold using malloc becomes more space efficient.
 */
#define MEM_POOL_MIN_ALLOCS_PER_PAGE 6

struct pool_allocator {
	 /* Allocation size */
	unsigned	size; 
	/* The number of chunks allocated on single page */
	unsigned	chunks_per_page;

	/* The list of allocated pages */
	struct cd_list	pgs_used; /* Partially used pages */
	struct cd_list	pgs_full; /* Full pages */

	/* Statistics */
	unsigned long long	pgs_cnt; /* Total pages in both lists */
};

struct mem_pool {
	/* Free page lists */
	struct cd_list	pgs_free;
	struct cd_list	pgs_standby;

	/* Standby links allocator */
	struct pool_allocator	standby_allocator;

	/* Statistics */
	unsigned long long	pgs_free_cnt;	/* The current number of free pages */
	unsigned long long	pgs_standby_cnt;/* The current number of standby pages */
	unsigned long long	pgs_allocated;	/* Total number of allocated pages */
};

/* Initialize pool */
PCS_API void pool_init(struct mem_pool* p);

/* Initialize pool allocator, may return -1 if the size is not suitable for the pool allocation. */
PCS_API int pool_allocator_init(struct pool_allocator* a, unsigned size);

/* Check if pool allocator was initialized successfully */
static inline int pool_allocator_valid(struct pool_allocator* a)
{
	return a->chunks_per_page > 0;
}

/* Allocate chunk */
PCS_API void* pool_alloc(struct mem_pool* p, struct pool_allocator* a);

/* Release chunk */
PCS_API void pool_free(struct mem_pool* p, struct pool_allocator* a, void* ptr);
