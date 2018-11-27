/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#define PCS_MALLOC_POISON_DISABLE
#include "pcs_malloc.h"
#include "pcs_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "pcs_atomic.h"

void __noinline pcs_malloc_failed(const char *file)
{
	pcs_log(LOG_ERR, "Fatal: failed to allocate memory at %s", file);
	BUG();
}

#define PAGE_SIZE 4096
#define pcs_get_size(size) (intptr_t)(size)

static pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct malloc_item *mi_list = NULL;

static int pcs_malloc_enabled = 0;

void pcs_malloc_debug_enable(void)
{
	pcs_malloc_enabled = 1;
}

static void pcs_malloc_item_init(struct malloc_item **tr, const char *file)
{
	pcs_malloc_item_init_(tr, file, 0);
}

void pcs_account_alloc(struct malloc_item *mi, intptr_t size)
{
	pthread_mutex_lock(&mi->mutex);
	BUG_ON(-size > (intptr_t)mi->allocated);
	mi->allocated += size;
	if (size > 0) {
		++mi->alloc_cnt;
		if (size > mi->max_size)
			mi->max_size = size;
		if (mi->allocated > mi->max_allocated)
			mi->max_allocated = mi->allocated;
	}
	if (size < 0) {
		++mi->free_cnt;
	}
	pthread_mutex_unlock(&mi->mutex);
}

#ifdef TRACE_ALLOC_SLOW

#include "jhash.h"

#define MI_HASH_SIZE	32768
static struct malloc_item *mi_hash[MI_HASH_SIZE];

static struct malloc_item *hash_lookup(u32 hash, const char *file)
{
	volatile struct malloc_item *mi;
	for (mi = mi_hash[hash]; mi; mi = mi->hash_next)
		if (mi->file == file)
			return (struct malloc_item *)mi;
	return NULL;
}

void pcs_malloc_item_init_(struct malloc_item **p_mi, const char *file, u32 flags)
{
	if (unlikely(!pcs_malloc_enabled)) {
		*p_mi = NULL;
		return;
	}

	/* fast path: it's ok to walk through hash table w/o mutex as we never remove items from it */
	u32 hash = jhash3((u32)(((ULONG_PTR)file) >> 3), (u32)((ULONG_PTR)file), (u32)(((ULONG_PTR)file) >> 24), *(u32*)file);
	hash &= (MI_HASH_SIZE - 1);
	struct malloc_item *mi = hash_lookup(hash, file);
	if (likely(mi)) {
		*p_mi = mi;
		return;
	}

	struct malloc_item *new_mi = malloc(sizeof(struct malloc_item));
	if (unlikely(!new_mi))
		pcs_malloc_failed(file);

	pthread_mutex_lock(&global_mutex);
	/* relookup under mutex to make sure nobody allocated it yet */
	mi = hash_lookup(hash, file);
	if (likely(!mi)) {
		mi = new_mi;
		new_mi = NULL;
		mi->allocated = 0;
		mi->max_size  = 0;
		mi->max_allocated = 0;
		mi->alloc_cnt = 0;
		mi->free_cnt  = 0;
		mi->file = file;
		pthread_mutex_init(&mi->mutex, NULL);
		mi->next = mi_list;
		mi->flags = flags;
		mi_list = mi;
		mi->hash_next = mi_hash[hash];
		pcs_wmb();
		mi_hash[hash] = mi;
	}
	pthread_mutex_unlock(&global_mutex);
	free(new_mi);

	*p_mi = mi;
}

#else	/* TRACE_ALLOC_SLOW */

void pcs_malloc_item_init_(struct malloc_item **pointer, const char *file, u32 flags)
{
	if (likely(*pointer) || unlikely(!pcs_malloc_enabled))
		return;

	struct malloc_item *mi = malloc(sizeof(struct malloc_item));
	if (unlikely(!mi))
		pcs_malloc_failed(file);

	pthread_mutex_lock(&global_mutex);
	if (unlikely(*pointer == NULL)) {
		mi->allocated = 0;
		mi->max_size  = 0;
		mi->max_allocated = 0;
		mi->alloc_cnt = 0;
		mi->free_cnt  = 0;
		mi->file = file;
		mi->next = mi_list;
		mi->flags = flags;
		pthread_mutex_init(&mi->mutex, NULL);
		mi_list = mi;
		*pointer = mi;
		mi = NULL;
	}
	pthread_mutex_unlock(&global_mutex);
	free(mi);
}

#endif	/* TRACE_ALLOC_SLOW */

void *__pcs_malloc(struct malloc_item *mi, const char *file, int check, size_t size)
{
	void *ptr = NULL;
	if (unlikely(!pcs_malloc_enabled)) {
		ptr = malloc(size);
		goto done;
	}
	if (unlikely(!mi))
		pcs_malloc_item_init(&mi, file);

	struct mem_header *hdr = malloc(size + sizeof(struct mem_header));
	if (unlikely(!hdr))
		goto done;

	pcs_account_alloc(mi, size);
	pcs_fill_mem_header(hdr, mi, size);
	ptr = hdr + 1;

done:
	if (unlikely(check && !ptr))
		pcs_malloc_failed(file);
	return ptr;
}

void *__pcs_zmalloc(struct malloc_item *mi, const char *file, int check, size_t size)
{
	void *ptr = __pcs_malloc(mi, file, check, size);
	if (likely(ptr))
		memset(ptr, 0, size);
	return ptr;
}

void *__pcs_realloc(struct malloc_item *mi, const char *file, int check, void *block, size_t size)
{
	void *ptr = NULL;

	if (unlikely(!pcs_malloc_enabled)) {
		ptr = realloc(block, size);
		goto done;
	}
	if (unlikely(!mi))
		pcs_malloc_item_init(&mi, file);
	if (unlikely(!block))
		return __pcs_malloc(mi, file, check, size);
	if (unlikely(!size)) {
		__pcs_free(block);
		return NULL;
	}

	struct mem_header* hdr = (struct mem_header*) ((char*)block - sizeof(struct mem_header));
	if (unlikely(hdr->magic != PCS_MALLOC_MAGIC)) {
		pcs_log(LOG_ERR, "Fatal: corrupted memory - no magic (%p, %p, %llu)", block, hdr, (unsigned long long)size);
		BUG();
	}

	intptr_t init_size = pcs_get_size(hdr->size);

	mi = hdr->caller;

	hdr = realloc ((void*) hdr, size + sizeof(struct mem_header));
	if (unlikely(!hdr))
		goto done;

	pcs_account_alloc(mi, -init_size + size);
	hdr->size = size;
	ptr = hdr + 1;
done:
	if (unlikely(!ptr && check && size))
		pcs_malloc_failed(file);
	return ptr;
}

void __pcs_free(void *block)
{
	if (!pcs_malloc_enabled) {
		free(block);
		return;
	}
	if (block == NULL)
		return;
	struct mem_header* hdr = (struct mem_header*) block;
	hdr--;

	if (hdr->magic == PCS_DOUBLEFREE_MAGIC) {
		pcs_log(LOG_ERR, "Fatal: double free of %p", hdr);
		BUG();
	}

	if (hdr->magic != PCS_MALLOC_MAGIC) {
		pcs_log(LOG_ERR, "Fatal: corrupted memory on free - no magic (%p, %p)", block, hdr);
		BUG();
	}

	hdr->magic = PCS_DOUBLEFREE_MAGIC;
	pcs_account_alloc(hdr->caller, -pcs_get_size(hdr->size));

	free(hdr);
}

/* add accounted bytes to existing allocation */
void __pcs_alloc_account(void *block, ptrdiff_t size)
{
	if (!pcs_malloc_enabled)
		return;
	if (block == NULL)
		return;

	struct mem_header* hdr = (struct mem_header*)block - 1;

	BUG_ON(size < 0 && hdr->size < -size);
	hdr->size += size;
	pcs_account_alloc(hdr->caller, size);
}

char *__pcs_strdup(struct malloc_item *mi, const char *file, int check, const char *src)
{
	char *ptr = NULL;
	if (unlikely(!pcs_malloc_enabled)) {
		ptr = strdup(src);
		goto done;
	}
	if (unlikely(!mi))
		pcs_malloc_item_init(&mi, file);

	size_t size = strlen(src) + 1;
	struct mem_header* hdr = malloc (size + sizeof(struct mem_header));
	if (unlikely(!hdr))
		goto done;
	pcs_account_alloc(mi, size);
	pcs_fill_mem_header(hdr, mi, size);
	hdr++;
	ptr = memcpy(hdr, src, size);
done:
	if (unlikely(check && !ptr))
		pcs_malloc_failed(file);
	return ptr;
}

char *__pcs_strndup(struct malloc_item *mi, const char *file, int check, const char *src, size_t size)
{
	char *ptr = NULL;
	if (unlikely(!pcs_malloc_enabled)) {
		ptr = strndup(src, size);
		goto done;
	}
	if (unlikely(!mi))
		pcs_malloc_item_init(&mi, file);

	size_t len = strnlen(src, size);
	size = ((len < size) ? len : size) + 1;
	struct mem_header* hdr = malloc (size + sizeof(struct mem_header));
	if (unlikely(!hdr))
		goto done;
	pcs_account_alloc(mi, size);
	pcs_fill_mem_header(hdr, mi, size);
	hdr++;
	ptr = memcpy(hdr, src, size - 1);
	ptr[size - 1] = '\0';
done:
	if (unlikely(check && !ptr))
		pcs_malloc_failed(file);
	return ptr;
}

static inline char malloc_item_prefix(struct malloc_item *p)
{
	if (p->flags & PCS_MALLOC_F_POOL)
		return '+';
	if (p->flags & PCS_MALLOC_F_IN_POOL)
		return '-';
	return ' ';
}

void pcs_malloc_dump(int level)
{
	struct malloc_item *p;
	pcs_log(level, "---====== PCS MALLOC DUMP ======---");
	if (pcs_malloc_enabled) {
		unsigned long long total_allocated = 0;
		pcs_log(level, "  bytes alloc_cnt free_cnt max_size max_alloc file:line");
		for (p = mi_list; p != NULL; p = p->next) {
			pcs_log(level, "%7llu %7llu %7llu %7llu %10llu %c%s",
				(unsigned long long)p->allocated,
				p->alloc_cnt, p->free_cnt,
				(unsigned long long)p->max_size,
				(unsigned long long)p->max_allocated,
				malloc_item_prefix(p),
				p->file
			);
			if (!(p->flags & PCS_MALLOC_F_IN_POOL))
				total_allocated += p->allocated;
		}
		pcs_log(level, "total %llu bytes allocated", total_allocated);
	} else
		pcs_log(level, "malloc debug is not enabled");
	pcs_log(level, "---====== MALLOC DUMP END ======---");
}

int pcs_malloc_stats(unsigned long long *total, unsigned long long *chunks)
{
	struct malloc_item *p;
	if (!pcs_malloc_enabled)
		return -1;

	unsigned long long total_sz = 0, chunks_cnt = 0;
	for (p = mi_list; p != NULL; p = p->next) {
		chunks_cnt += (p->alloc_cnt - p->free_cnt);
		total_sz += p->allocated;
	}
	*total = total_sz;
	*chunks = chunks_cnt;

	return 0;
}

int pcs_malloc_for_each_item(void (*fn)(struct malloc_item *p))
{
	struct malloc_item *p;

	if (!pcs_malloc_enabled)
		return -1;

	for (p = mi_list; p != NULL; p = p->next)
		fn(p);

	return 0;
}

char *__pcs_vasprintf(struct malloc_item *mi, const char *file, int check, const char *fmt, va_list va)
{
	va_list va2;
	va_copy(va2, va);
	int len = vsnprintf(NULL, 0, fmt, va2);
	va_end(va2);
	if (len < 0)
		return NULL;

	char *s = __pcs_malloc(mi, file, check, len + 1);
	if (!s)
		return NULL;

	if (vsnprintf(s, len + 1, fmt, va) != len)
		BUG();

	return s;
}

char *__pcs_asprintf(struct malloc_item *mi, const char *file, int check, const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	char *s = __pcs_vasprintf(mi, file, check, fmt, va);
	va_end(va);
	return s;
}
