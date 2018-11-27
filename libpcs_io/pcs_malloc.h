/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCS_MALLOC_H__
#define __PCS_MALLOC_H__

#include "pcs_types.h"
#include "pcs_thread.h"

#include <stddef.h>
#include <stdlib.h>	/* include stdlib before poisoning malloc/free - won't be includable later */
#include <stdarg.h>
#include <string.h>

#if !defined(__GNUC__) && !defined(__clang__)
/* if we can't use GCC ({ }) construction, then have to lookup malloc info each time using hash table */
#define TRACE_ALLOC_SLOW
#endif

#include <pthread.h>

struct malloc_item {
	const char *file;	/* saved as "file:line" */
	volatile size_t allocated;
	volatile size_t max_size;
	volatile size_t max_allocated;
	volatile unsigned long long alloc_cnt;
	volatile unsigned long long free_cnt;
	pthread_mutex_t mutex;
	struct malloc_item *next;
#ifdef TRACE_ALLOC_SLOW
	volatile struct malloc_item *hash_next;
#endif
	u32 flags;
};

#define PCS_MALLOC_F_POOL    1
#define PCS_MALLOC_F_IN_POOL 2
#define PCS_MALLOC_MAGIC 0xBA0BAB
#define PCS_DOUBLEFREE_MAGIC 0xDEAD0DAD

struct __pre_aligned(32) mem_header
{
	/* Header "magic" is needed for debug purposes to catch situation when
	 * user frees memory by pcs_free which is allocated by native malloc */
	u32 magic;
	size_t size;
	pthread_t tid;
	struct malloc_item *caller;
} __aligned(32);

static __inline void pcs_fill_mem_header(struct mem_header *mh,
		struct malloc_item *mi, size_t size)
{
	mh->magic = PCS_MALLOC_MAGIC;
	mh->caller = mi;
	mh->size = size;
	mh->tid = pcs_thread_self();
}

#define TRACE_STR2(x)   #x
#define TRACE_STR(x)	TRACE_STR2(x)

#ifdef TRACE_ALLOC_SLOW
#define TRACE_ALLOC(func, ...) \
	func(NULL, __FILE__ ":" TRACE_STR(__LINE__), __VA_ARGS__)
#else
#define TRACE_ALLOC(func, ...) \
	({ \
		static struct malloc_item *mi = NULL; \
		func(&mi, __FILE__ ":" TRACE_STR(__LINE__), __VA_ARGS__); \
	})
#endif

#define pcs_malloc(sz)			TRACE_ALLOC(__pcs_malloc, 0, sz)
#define pcs_zmalloc(sz)			TRACE_ALLOC(__pcs_zmalloc, 0, sz)
#define pcs_calloc(num, sz)		TRACE_ALLOC(__pcs_zmalloc, 0, num*sz)
#define pcs_realloc(ptr, sz)		TRACE_ALLOC(__pcs_realloc, 0, ptr, sz)
#define pcs_strdup(src)			TRACE_ALLOC(__pcs_strdup, 0, src)
#define pcs_strndup(src, sz)		TRACE_ALLOC(__pcs_strndup, 0, src, sz)
#define pcs_asprintf(fmt, ...)		TRACE_ALLOC(__pcs_asprintf, 0, fmt, ##__VA_ARGS__)
#define pcs_vasprintf(fmt, va)		TRACE_ALLOC(__pcs_vasprintf, 0, fmt, va)

#define pcs_xmalloc(sz)			TRACE_ALLOC(__pcs_malloc, 1, sz)
#define pcs_xzmalloc(sz)		TRACE_ALLOC(__pcs_zmalloc, 1, sz)
#define pcs_xrealloc(ptr, sz)		TRACE_ALLOC(__pcs_realloc, 1, ptr, sz)
#define pcs_xstrdup(src)		TRACE_ALLOC(__pcs_strdup, 1, src)
#define pcs_xstrndup(src, sz)		TRACE_ALLOC(__pcs_strndup, 1, src, sz)
#define pcs_xasprintf(fmt, ...)		TRACE_ALLOC(__pcs_asprintf, 1, fmt, ##__VA_ARGS__)
#define pcs_xvasprintf(fmt, va)		TRACE_ALLOC(__pcs_vasprintf, 1, fmt, va)

#define pcs_free			__pcs_free	/* no macro arg!!! otherwise won't be possible to take address of function */
#define pcs_alloc_account(ptr, sz)	__pcs_alloc_account(ptr, sz)

struct malloc_item *pcs_malloc_item_init(struct malloc_item **p_mi, const char *file, u32 flags);

void pcs_account_alloc(struct malloc_item *mi, intptr_t size);

PCS_API void *__pcs_malloc(struct malloc_item **p_mi, const char *file, int check, size_t size);
PCS_API void *__pcs_zmalloc(struct malloc_item **p_mi, const char *file, int check, size_t size);
PCS_API char *__pcs_strdup(struct malloc_item **p_mi, const char *file, int check, const char *src);
PCS_API char *__pcs_strndup(struct malloc_item **p_mi, const char *file, int check, const char *src, size_t size);
PCS_API void *__pcs_realloc(struct malloc_item **p_mi, const char *file, int check, void *block, size_t size);
PCS_API char *__pcs_asprintf(struct malloc_item **p_mi, const char *file, int check, const char *fmt, ...) __printf(4, 5);
PCS_API char *__pcs_vasprintf(struct malloc_item **p_mi, const char *file, int check, const char *fmt, va_list va);

PCS_API void __pcs_free(void *ptr);
PCS_API void __pcs_alloc_account(void *ptr, ptrdiff_t sz);
PCS_API void pcs_malloc_dump(int level);
PCS_API int pcs_malloc_stats(unsigned long long *total, unsigned long long *chunks);
PCS_API int pcs_malloc_for_each_item(void (*fn)(struct malloc_item *m));

void pcs_malloc_failed(const char *file);

#define pcs_native_malloc(sz)		malloc(sz)
#define pcs_native_calloc(num, sz)	calloc(num, sz)
#define pcs_native_strdup(src)		strdup(src)
#define pcs_native_strndup(src, sz)	strndup(src, sz)
#define pcs_native_realloc(ptr, sz)	realloc(ptr, sz)
#define pcs_native_free(ptr)		free(ptr)

PCS_API void pcs_malloc_debug_enable(void);

#if (defined(__GNUC__) || defined(__clang__)) && !defined(PCS_MALLOC_POISON_DISABLE)
#undef strndup
#undef malloc
#undef calloc
#undef realloc
#undef free
#undef strdup
#undef strndup
#undef posix_memalign
#pragma GCC poison malloc calloc realloc free memalign posix_memalign strdup strndup pcs_memalign
#endif

#endif /* __PCS_MALLOC_H__ */
