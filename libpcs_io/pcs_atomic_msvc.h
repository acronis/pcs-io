/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

/* This file should not be included directly, include pcs_atomic.h instead */

#include <intrin.h>

typedef struct {
	volatile long val;
} pcs_atomic32_t;
typedef struct {
	volatile __int64 val;
} pcs_atomic64_t;

static inline void pcs_atomic32_store(pcs_atomic32_t *obj, s32 val)
{
	obj->val = val;
}

static inline s32 pcs_atomic32_load(pcs_atomic32_t *obj)
{
	return obj->val;
}

static inline s32 pcs_atomic32_fetch_and_add(pcs_atomic32_t *obj, s32 val)
{
	return _InterlockedExchangeAdd(&obj->val, val);
}

static inline void pcs_atomic32_add(pcs_atomic32_t *obj, s32 val)
{
	pcs_atomic32_fetch_and_add(obj, val);
}

static inline s32 pcs_atomic32_fetch_and_sub(pcs_atomic32_t *obj, s32 val)
{
	return pcs_atomic32_fetch_and_add(obj, -val);
}

static inline void pcs_atomic32_sub(pcs_atomic32_t *obj, s32 val)
{
	pcs_atomic32_fetch_and_sub(obj, val);
}

static inline s32 pcs_atomic32_fetch_and_inc(pcs_atomic32_t *obj)
{
	return _InterlockedIncrement(&obj->val) - 1;
}

static inline void pcs_atomic32_inc(pcs_atomic32_t *obj)
{
	pcs_atomic32_fetch_and_inc(obj);
}

static inline s32 pcs_atomic32_fetch_and_dec(pcs_atomic32_t *obj)
{
	return _InterlockedDecrement(&obj->val) + 1;
}

static inline void pcs_atomic32_dec(pcs_atomic32_t *obj)
{
	pcs_atomic32_fetch_and_dec(obj);
}

static inline s32 pcs_atomic32_fetch_and_and(pcs_atomic32_t *obj, s32 val)
{
	return _InterlockedAnd(&obj->val, val);
}

static inline void pcs_atomic32_and(pcs_atomic32_t *obj, s32 val)
{
	pcs_atomic32_fetch_and_and(obj, val);
}

static inline s32 pcs_atomic32_fetch_and_or(pcs_atomic32_t *obj, s32 val)
{
	return _InterlockedOr(&obj->val, val);
}

static inline void pcs_atomic32_or(pcs_atomic32_t *obj, s32 val)
{
	pcs_atomic32_fetch_and_or(obj, val);
}

static inline s32 pcs_atomic32_fetch_and_xor(pcs_atomic32_t *obj, s32 val)
{
	return _InterlockedXor(&obj->val, val);
}

static inline void pcs_atomic32_xor(pcs_atomic32_t *obj, s32 val)
{
	pcs_atomic32_fetch_and_xor(obj, val);
}

static inline s32 pcs_atomic32_exchange(pcs_atomic32_t *obj, s32 val)
{
	return _InterlockedExchange(&obj->val, val);
}

static inline s32 pcs_atomic32_cas(pcs_atomic32_t *obj, s32 old_val, s32 new_val)
{
	return _InterlockedCompareExchange(&obj->val, new_val, old_val);
}

static inline s64 pcs_atomic64_cas(pcs_atomic64_t *obj, s64 old_val, s64 new_val)
{
	return _InterlockedCompareExchange64(&obj->val, new_val, old_val);
}

#ifdef _WIN64

typedef struct {
	volatile __int64 val;
} pcs_atomic_ptr_t;

static inline void pcs_atomic64_store(pcs_atomic64_t *obj, s64 val)
{
	obj->val = val;
}

static inline s64 pcs_atomic64_load(pcs_atomic64_t *obj)
{
	return obj->val;
}

static inline s64 pcs_atomic64_fetch_and_add(pcs_atomic64_t *obj, s64 val)
{
	return _InterlockedExchangeAdd64(&obj->val, val);
}

static inline s64 pcs_atomic64_fetch_and_inc(pcs_atomic64_t *obj)
{
	return _InterlockedIncrement64(&obj->val) - 1;
}

static inline s64 pcs_atomic64_fetch_and_dec(pcs_atomic64_t *obj)
{
	return _InterlockedDecrement64(&obj->val) + 1;
}

static inline s64 pcs_atomic64_exchange(pcs_atomic64_t *obj, s64 val)
{
	return _InterlockedExchange64(&obj->val, val);
}

static inline s64 pcs_atomic64_fetch_and_and(pcs_atomic64_t *obj, s64 val)
{
	return _InterlockedAnd64(&obj->val, val);
}

static inline s64 pcs_atomic64_fetch_and_or(pcs_atomic64_t *obj, s64 val)
{
	return _InterlockedOr64(&obj->val, val);
}

static inline s64 pcs_atomic64_fetch_and_xor(pcs_atomic64_t *obj, s64 val)
{
	return _InterlockedXor64(&obj->val, val);
}

static inline ULONG_PTR pcs_atomic_uptr_exchange(pcs_atomic_ptr_t *obj, ULONG_PTR val)
{
	return _InterlockedExchange64(&obj->val, val);
}

static inline ULONG_PTR pcs_atomic_uptr_cas(pcs_atomic_ptr_t *obj, ULONG_PTR old_val, ULONG_PTR new_val)
{
	return _InterlockedCompareExchange64(&obj->val, new_val, old_val);
}

#else /* WIN64 */

typedef struct {
	volatile long val;
} pcs_atomic_ptr_t;

static inline s64 pcs_atomic64_load(pcs_atomic64_t *obj)
{
	return pcs_atomic64_cas(obj, 0, 0);
}

static inline s64 pcs_atomic64_exchange(pcs_atomic64_t *obj, s64 val)
{
	s64 old_val = obj->val;
	for (;;) {
		s64 cur_val = pcs_atomic64_cas(obj, old_val, val);
		if (cur_val == old_val)
			break;

		old_val = cur_val;
	}
	return old_val;
}

static inline void pcs_atomic64_store(pcs_atomic64_t *obj, s64 val)
{
	pcs_atomic64_exchange(obj, val);
}

static inline s64 pcs_atomic64_fetch_and_add(pcs_atomic64_t *obj, s64 val)
{
	s64 old_val = obj->val;
	for (;;) {
		s64 cur_val = pcs_atomic64_cas(obj, old_val, old_val + val);
		if (cur_val == old_val)
			break;

		old_val = cur_val;
	}
	return old_val;
}

static inline s64 pcs_atomic64_fetch_and_inc(pcs_atomic64_t *obj)
{
	return pcs_atomic64_fetch_and_add(obj, 1);
}

static inline s64 pcs_atomic64_fetch_and_dec(pcs_atomic64_t *obj)
{
	return pcs_atomic64_fetch_and_add(obj, -1);
}

static inline s64 pcs_atomic64_fetch_and_and(pcs_atomic64_t *obj, s64 val)
{
	s64 old_val = obj->val;
	for (;;) {
		s64 cur_val = pcs_atomic64_cas(obj, old_val, old_val & val);
		if (cur_val == old_val)
			break;

		old_val = cur_val;
	}
	return old_val;
}

static inline s64 pcs_atomic64_fetch_and_or(pcs_atomic64_t *obj, s64 val)
{
	s64 old_val = obj->val;
	for (;;) {
		s64 cur_val = pcs_atomic64_cas(obj, old_val, old_val | val);
		if (cur_val == old_val)
			break;

		old_val = cur_val;
	}
	return old_val;
}

static inline s64 pcs_atomic64_fetch_and_xor(pcs_atomic64_t *obj, s64 val)
{
	s64 old_val = obj->val;
	for (;;) {
		s64 cur_val = pcs_atomic64_cas(obj, old_val, old_val ^ val);
		if (cur_val == old_val)
			break;

		old_val = cur_val;
	}
	return old_val;
}

static inline ULONG_PTR pcs_atomic_uptr_exchange(pcs_atomic_ptr_t *obj, ULONG_PTR val)
{
	return _InterlockedExchange(&obj->val, val);
}

static inline ULONG_PTR pcs_atomic_uptr_cas(pcs_atomic_ptr_t *obj, ULONG_PTR old_val, ULONG_PTR new_val)
{
	return _InterlockedCompareExchange(&obj->val, new_val, old_val);
}

#endif /* WIN64 */

static inline void pcs_atomic64_add(pcs_atomic64_t *obj, s64 val)
{
	pcs_atomic64_fetch_and_add(obj, val);
}

static inline s64 pcs_atomic64_fetch_and_sub(pcs_atomic64_t *obj, s64 val)
{
	return pcs_atomic64_fetch_and_add(obj, -val);
}

static inline void pcs_atomic64_sub(pcs_atomic64_t *obj, s64 val)
{
	pcs_atomic64_fetch_and_sub(obj, val);
}

static inline void pcs_atomic64_inc(pcs_atomic64_t *obj)
{
	pcs_atomic64_fetch_and_inc(obj);
}

static inline void pcs_atomic64_dec(pcs_atomic64_t *obj)
{
	pcs_atomic64_fetch_and_dec(obj);
}

static inline void pcs_atomic64_and(pcs_atomic64_t *obj, s64 val)
{
	pcs_atomic64_fetch_and_and(obj, val);
}

static inline void pcs_atomic64_or(pcs_atomic64_t *obj, s64 val)
{
	pcs_atomic64_fetch_and_or(obj, val);
}

static inline void pcs_atomic64_xor(pcs_atomic64_t *obj, s64 val)
{
	pcs_atomic64_fetch_and_xor(obj, val);
}

static inline void pcs_atomic_uptr_store(pcs_atomic_ptr_t *obj, ULONG_PTR val)
{
	obj->val = val;
}

static inline ULONG_PTR pcs_atomic_uptr_load(pcs_atomic_ptr_t *obj)
{
	return obj->val;
}

static inline void pcs_compiler_mb(void)
{
	_ReadWriteBarrier();
}

#ifdef _M_ARM

static inline void pcs_rmb()
{
	__dmb(_ARM_BARRIER_ISH);
}

static inline void pcs_wmb()
{
	__dmb(_ARM_BARRIER_ISH);
}

static inline void pcs_mb(void)
{
	__dmb(_ARM_BARRIER_ISH);
}

#else

static inline void pcs_rmb()
{
	_ReadBarrier();
}

static inline void pcs_wmb()
{
	_WriteBarrier();
}

static inline void pcs_mb(void)
{
	_mm_mfence();
}

#endif
