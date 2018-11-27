/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCS_ALIGN_H__
#define __PCS_ALIGN_H__

#include "pcs_types.h"

/* ----- helpers ----- */

#if defined(__GNUC__) || defined(__clang__)

#define __pre_aligned(x)
#define __aligned(x)		__attribute__((__aligned__(x)))
#define __pre_packed
#define __packed		__attribute__((packed))
#define __unaligned		__attribute__((packed, may_alias))

#elif defined(_MSC_VER)

#define __pre_aligned(x)	__declspec(align(x))
#define __aligned(x)
#define __pre_packed		__pragma(pack(push,1))
#define __packed		; __pragma(pack(pop))
/* MSVC can't target platforms with unaligned access problems, so we can ignore this attribute */
#define __unaligned

#endif

#define PCS_ALIGN_TO(sz, align) (((sz)+(align)-1)&~((align)-1))
#define PCS_ALIGN(sz) PCS_ALIGN_TO(sz, 8)

#define __PCS_UNALIGNED2(type, suff)									\
typedef union { type v; } __unaligned pcs_unaligned_ ## suff ## _t;					\
static inline type pcs_get_unaligned_ ## suff (const void *p) { return ((const pcs_unaligned_ ## suff ## _t *)p)->v; }
#define __PCS_UNALIGNED(size) __PCS_UNALIGNED2(u ## size, size)

__PCS_UNALIGNED(16)			/* pcs_get_unaligned_16() */
__PCS_UNALIGNED(32)			/* pcs_get_unaligned_32() */
__PCS_UNALIGNED(64)			/* pcs_get_unaligned_64() */
__PCS_UNALIGNED2(ULONG_PTR, ptr)	/* pcs_get_unaligned_ptr() */

/* This macros are used only to generate unaligned getters */
#undef __unaligned
#undef __PCS_UNALIGNED
#undef __PCS_UNALIGNED2

#endif /* __PCS_ALIGN_H__ */
