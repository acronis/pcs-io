/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_ATOMIC_H_
#define _PCS_ATOMIC_H_

#include "pcs_types.h"

/**
 * This is a pcs atomic API
 *
 * Under GCC and clang we use <stdatomic.h> if it is available
 * If it is not, we use gnu built-in atomic API: https://gcc.gnu.org/onlinedocs/gcc-4.5.4/gcc/Atomic-Builtins.html
 * Under MSVC we use its atomic intrinsics: https://msdn.microsoft.com/en-us/library/hh977022.aspx
 *
 * Currently, we have 2 data types -- pcs_atomic32_t and pcs_atomic64_t
 *
 * List of available functions:
 *
 * 1.
 * void pcs_atomic32_store(pcs_atomic32_t *obj, s32 val)
 * sets the value of @obj to @val
 *
 * 2.
 * s32 pcs_atomic_load(pcs_atomic32_t *obj)
 * returns the value of @obj
 *
 * 3.
 * s32 pcs_atomic32_fetch_and_add(pcs_atomic32_t *obj, s32 val)
 * returns the old value of @obj and then adds @val to it
 *
 * 4.
 * void pcs_atomic32_add(pcs_atomic32_t *obj, s32 val)
 * same as the function above but without fetching the old value
 *
 * 5.
 * s32 pcs_atomic32_fetch_and_sub(pcs_atomic32_t *obj, s32 val)
 * returns the old value of @obj and then subtracts @val from it
 *
 * 6.
 * void pcs_atomic32_sub(pcs_atomic32_t *obj, s32 val)
 * same as the function above but without fetching the old value
 *
 * 7.
 * void pcs_atomic32_fetch_and_inc(pcs_atomic32_t *obj)
 * returns the old value of @obj and then increments @obj by 1
 *
 * 8.
 * void pcs_atomic32_inc(pcs_atomic32_t *obj)
 * same as the function above but without fetching the old value
 *
 * 9.
 * void pcs_atomic32_fetch_and_dec(pcs_atomic32_t *obj)
 * returns the old value of @obj and then decrements @obj by 1
 *
 * 10.
 * void pcs_atomic32_dec(pcs_atomic32_t *obj)
 * same as the function above but without fetching the old value
 *
 * 11.
 * s32 pcs_atomic32_cas(pcs_atomic32_t *obj, s32 old_val, s32 new_val)
 * if the value of @obj is equal to @old_val, sets it to @new_val
 * regardles of its success, returs the value of @obj at the begginning of this operation
 *
 *
 * The same list of fuctions is available with _s64 suffix
 *
 *
 * Implementation of memory barriers for ARM and x86 architectures.
 * As x86 has a strong memory model, we mostly need it for ARM architecture.
 *
 * Hardware memory barriers:
 *
 * 1.
 * void pcs_rmb(void)
 * read memory barrier (#LoadLoad semantics)
 *
 * 2.
 * void pcs_wmb(void)
 * write memory barrier (#StoreStore semantics)
 *
 * 3.
 * void pcs_mb(void)
 * full memory barrier (#LoadLoad + #LoadStore + #StoreStre + #StoreLoad semantics)
 *
 * Compiler memory barrier:
 *
 * 1.
 * void pcs_compiler_mb()
 * full compiler barrier
 */

#if defined(__GNUC__) || defined(__clang__)
#include "pcs_atomic_gcc.h"
#elif defined(_MSC_VER)
#include "pcs_atomic_msvc.h"
#else
#error "Unknown compiler"
#endif

static inline void pcs_atomic_ptr_store(pcs_atomic_ptr_t *obj, void *val)
{
        pcs_atomic_uptr_store(obj, (ULONG_PTR)val);
}

static inline void *pcs_atomic_ptr_load(pcs_atomic_ptr_t *obj)
{
	return (void *)pcs_atomic_uptr_load(obj);
}

static inline void *pcs_atomic_ptr_exchange(pcs_atomic_ptr_t *obj, void *val)
{
	return (void *)pcs_atomic_uptr_exchange(obj, (ULONG_PTR)val);
}

static inline void *pcs_atomic_ptr_cas(pcs_atomic_ptr_t *obj, void *old_val, void *new_val)
{
	return (void *)pcs_atomic_uptr_cas(obj, (ULONG_PTR)old_val, (ULONG_PTR)new_val);
}

#endif /* _PCS_ATOMIC_H_ */
