/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_types.h"
#include "pool_allocator.h"
#include "log.h"

#include <string.h>
#ifndef __WINDOWS__
#include <sys/mman.h>
#endif

#ifndef PAGE_SIZE
#ifdef __aarch64__
#define PAGE_SIZE 0x10000
#else
#define PAGE_SIZE 0x1000
#endif
#endif

/* The allocator uses memory mapped pages splitting them onto chunks with chunk header
 * required for free chunk only so it is not consuming additional space. Free pages
 * are not unmapped to avoid virtual address space fragmentation. Instead they are
 * going onto 'standby' state by calling madvise(MADV_DONTNEED). While the page
 * is in the standby state we are keeping only external reference to it in 
 * the struct standby_link allocated from the dedicated pool.
 */

struct pool_chunk_hdr {
	struct pool_chunk_hdr*	next;
};

struct pool_page_hdr {
	struct pool_chunk_hdr*	free_chunks;	/* Free chunk list */
	struct cd_list		node;		/* List node */
	unsigned		chunks_used;	/* Used chunks count */
};

struct standby_link {
	struct cd_list		node;	/* List node */
	struct pool_page_hdr*	pg;	/* Pointer to standby page */			
};

#define MMAP_ATTR (MAP_ANONYMOUS|MAP_PRIVATE)
#ifdef __linux__
#define MADV_ATTR MADV_DONTNEED
#else // MacOS, Solaris
#define MADV_ATTR MADV_FREE
#endif

#define POOL_ALIGN(sz) (((sz) + MEM_POOL_ALLOC_ALIGN - 1) & ~(MEM_POOL_ALLOC_ALIGN - 1))
#define PAGE_PTR(p)    ((void*)((long)(p) & ~(long)(PAGE_SIZE-1)))

BUILD_BUG_ON(MEM_POOL_ALLOC_ALIGN < sizeof(struct pool_chunk_hdr));

#ifdef MEM_POOL_DEBUG
#define MAX_CHUNKS_PER_PAGE 1
#endif

/* Initialize pool */
void pool_init(struct mem_pool* p)
{
	int res;
	memset(p, 0, sizeof(*p));
	cd_list_init(&p->pgs_free);
	cd_list_init(&p->pgs_standby);
	res = pool_allocator_init(&p->standby_allocator, sizeof(struct standby_link));
	BUG_ON(res);
}

/* Initialize pool allocator, may return -1 if the size is not suitable for the pool allocation. */
int pool_allocator_init(struct pool_allocator* a, unsigned size)
{
	unsigned chunks;

	memset(a, 0, sizeof(*a));

	if (!size)
		return -1;

	chunks = (PAGE_SIZE - POOL_ALIGN(sizeof(struct pool_page_hdr))) / POOL_ALIGN(size);
	if (chunks < MEM_POOL_MIN_ALLOCS_PER_PAGE)
		return -1;

#ifdef MAX_CHUNKS_PER_PAGE
	if (chunks > MAX_CHUNKS_PER_PAGE)
		chunks = MAX_CHUNKS_PER_PAGE;
#endif
	a->chunks_per_page = chunks;
	a->size = size;

	cd_list_init(&a->pgs_used);
	cd_list_init(&a->pgs_full);

	return 0;
}

/* Add page to free list */
static inline void add_free_page(struct mem_pool* p, struct pool_page_hdr* pg)
{
	cd_list_add(&pg->node, &p->pgs_free);
	++p->pgs_free_cnt;
}

/* Add page to standby list */
static unsigned add_standby_page(struct mem_pool* p, struct pool_page_hdr* pg)
{
	int res;
	struct standby_link* l = pool_alloc(p, &p->standby_allocator);
	if (!l)
		return 0;

	/* Standby page will loose its content so we have to create external reference to the page */
	l->pg = pg;

#ifdef MEM_POOL_GUARD
	/* The FIFO semantic ensure standby list rotation maximizing the 
	 * time the particular page is spending in the list.
	 */
	cd_list_add_tail(&l->node, &p->pgs_standby);
#else
	/* Following the LIFO semantic seems more performance friendly
	 * since the last added page has less chances to be swapped out.
	 */
	cd_list_add(&l->node, &p->pgs_standby);
#endif

	++p->pgs_standby_cnt;

#ifdef MEM_POOL_GUARD
	/* Protect page to detect access */
	res = mprotect(pg, PAGE_SIZE, PROT_NONE);
	BUG_ON(res);
#endif
#ifndef __WINDOWS__
	res = madvise((void *)pg, PAGE_SIZE, MADV_ATTR);
#endif
	(void)res;

	return 1;
}

/* Move page from standby list to free list */
static unsigned retrieve_standby_page(struct mem_pool* p)
{
	struct standby_link* l;
	struct pool_page_hdr* pg;

	if (!p->pgs_standby_cnt)
		return 0;

	l = cd_list_first_entry(&p->pgs_standby, struct standby_link, node);

	pg = l->pg;
	BUG_ON(!pg);

	cd_list_del(&l->node);
	pool_free(p, &p->standby_allocator, l);
	--p->pgs_standby_cnt;

#ifdef MEM_POOL_GUARD
	/* Unprotect page */
	{
		int res = mprotect(pg, PAGE_SIZE, PROT_READ|PROT_WRITE);
		BUG_ON(res);
	}
#endif

	add_free_page(p, pg);
	return 1;
}

/* Allocate the number of free pages */
static unsigned prealloc_pages(struct mem_pool* p)
{
	void* ptr;
	unsigned i, pgs;
	struct pool_page_hdr* pg;

	for (pgs = MEM_POOL_PREALLOC_PGS; pgs; pgs /= 2)
	{
		unsigned sz = pgs * PAGE_SIZE;
#ifndef __WINDOWS__
		int res;
		ptr = mmap(0, sz, PROT_READ|PROT_WRITE, MMAP_ATTR, -1, 0);
		if (!ptr || ptr == MAP_FAILED)
			continue;
		res = madvise(ptr, sz, MADV_RANDOM);
		BUG_ON(res);
#else
		ptr = VirtualAlloc(0, sz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!ptr)
			continue;
#endif
		break;
	}

	if (!pgs)
		return 0;

	BUG_ON((long)ptr & (PAGE_SIZE - 1));
	pg = (struct pool_page_hdr*)ptr;

	for (i = 0; i < pgs; ++i)
	{
		add_free_page(p, pg);
		pg = (struct pool_page_hdr*)((char*)pg + PAGE_SIZE);
	}

	p->pgs_allocated += pgs;
	return pgs;
}

/* Allocate page from the pool */
static struct pool_page_hdr* alloc_page(struct mem_pool* p)
{
	struct pool_page_hdr* pg;

	if (!p->pgs_free_cnt) {
		/* No free pages available */
		do {
			/* Consider standby list first */
			if (retrieve_standby_page(p))
				break;
			/* Try to allocate free pages */
			if (prealloc_pages(p))
				break;
			return 0;
		} while (0);
	}

	BUG_ON(!p->pgs_free_cnt);
	BUG_ON(cd_list_empty(&p->pgs_free));

	pg = cd_list_first_entry(&p->pgs_free, struct pool_page_hdr, node);
	cd_list_del(&pg->node);
	--p->pgs_free_cnt;

	return pg;
}

#define MAX_FREE_PAGES (2*MEM_POOL_PREALLOC_PGS)

/* Release allocated page */
static void free_page(struct mem_pool* p, struct pool_page_hdr* pg)
{
	BUG_ON(pg->chunks_used);
	BUG_ON(!p->pgs_allocated);

	if (p->pgs_free_cnt >= MAX_FREE_PAGES && add_standby_page(p, pg))
		return;

	add_free_page(p, pg);
}

BUILD_BUG_ON(offsetof(struct pool_page_hdr, free_chunks) != offsetof(struct pool_chunk_hdr, next));

/* Add page to allocator */
static void add_pool_page(struct pool_allocator* a, struct pool_page_hdr* pg)
{
	unsigned i;
	struct pool_chunk_hdr* _ch = (struct pool_chunk_hdr*)pg;
	struct pool_chunk_hdr*  ch = (struct pool_chunk_hdr*)((char*)pg + POOL_ALIGN(sizeof(struct pool_page_hdr)));

	for (i = 0; i < a->chunks_per_page; ++i)
	{
		/* Note that at first pass we actually initialize list head */
		_ch->next = ch;
		_ch = ch;
		ch = (struct pool_chunk_hdr*)((char*)(ch) + POOL_ALIGN(a->size));
	}

	BUG_ON((char*)ch - (char*)pg > PAGE_SIZE);
	BUG_ON(PAGE_PTR(_ch) != pg);

	/* Terminate list (_ch points to the last element) */
	_ch->next = 0;
	pg->chunks_used = 0;
	cd_list_add(&pg->node, &a->pgs_used);
	++a->pgs_cnt;
}

/* Allocate chunk from the particular pool page */
static void* alloc_from_page(struct pool_allocator* a, struct pool_page_hdr* pg)
{
	struct pool_chunk_hdr* ch;
	BUG_ON(pg->chunks_used >= a->chunks_per_page);
	BUG_ON(!pg->free_chunks);

	ch = pg->free_chunks;
	pg->free_chunks = ch->next;
	++pg->chunks_used;

	if (!pg->free_chunks)
	{
		/* No free chunks left */
		BUG_ON(pg->chunks_used != a->chunks_per_page);
		cd_list_del(&pg->node);
		cd_list_add(&pg->node, &a->pgs_full);
	}

	return ch;
}

/* Allocate chunk */
void* pool_alloc(struct mem_pool* p, struct pool_allocator* a)
{
	void* ptr;
	struct pool_page_hdr* pg;

	BUG_ON(!pool_allocator_valid(a));
	if (!pool_allocator_valid(a))
		return 0;

	if (cd_list_empty(&a->pgs_used))
	{
		/* No partially used pages available, try to allocate the new one */
		pg = alloc_page(p);
		if (!pg)
			return 0;
		add_pool_page(a, pg);
	} else
		pg = cd_list_first_entry(&a->pgs_used, struct pool_page_hdr, node);

	ptr = alloc_from_page(a, pg);
	BUG_ON(!ptr);
	return ptr;
}

/* Release chunk */
void pool_free(struct mem_pool* p, struct pool_allocator* a, void* ptr)
{
	struct pool_chunk_hdr* ch = ptr;
	struct pool_page_hdr* pg = PAGE_PTR(ptr);

	BUG_ON(!pg->chunks_used);

	ch->next = pg->free_chunks;
	pg->free_chunks = ch;

	if (!ch->next)
	{
		/* This is the first free chunk */
		BUG_ON(pg->chunks_used != a->chunks_per_page);
		cd_list_del(&pg->node);
		cd_list_add(&pg->node, &a->pgs_used);
	}

	if (!--pg->chunks_used)
	{
		/* This was the last used chunk */
		BUG_ON(!a->pgs_cnt);
		cd_list_del(&pg->node);
		--a->pgs_cnt;
		free_page(p, pg);
	}
}
