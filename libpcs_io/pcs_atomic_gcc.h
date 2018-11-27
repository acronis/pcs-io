/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

/* This file should not be included directly, include pcs_atomic.h instead */

typedef struct {
	volatile s32 val;
} pcs_atomic32_t;
typedef struct {
	volatile s64 val;
} pcs_atomic64_t;
typedef struct {
	volatile ULONG_PTR val;
} pcs_atomic_ptr_t;

// ===== s32 =====

static inline void pcs_atomic32_store(pcs_atomic32_t *obj, s32 val)
{
	__atomic_store_n(&obj->val, val, __ATOMIC_RELAXED);
}

static inline s32 pcs_atomic32_load(pcs_atomic32_t *obj)
{
	return __atomic_load_n(&obj->val, __ATOMIC_RELAXED);
}

static inline s32 pcs_atomic32_fetch_and_add(pcs_atomic32_t *obj, s32 val)
{
	return __atomic_fetch_add(&obj->val, val, __ATOMIC_SEQ_CST);
}

static inline void pcs_atomic32_add(pcs_atomic32_t *obj, s32 val)
{
	pcs_atomic32_fetch_and_add(obj, val);
}

static inline s32 pcs_atomic32_fetch_and_sub(pcs_atomic32_t *obj, s32 val)
{
	return __atomic_fetch_sub(&obj->val, val, __ATOMIC_SEQ_CST);
}

static inline void pcs_atomic32_sub(pcs_atomic32_t *obj, s32 val)
{
	pcs_atomic32_fetch_and_sub(obj, val);
}

static inline s32 pcs_atomic32_fetch_and_inc(pcs_atomic32_t *obj)
{
	return pcs_atomic32_fetch_and_add(obj, 1);
}

static inline void pcs_atomic32_inc(pcs_atomic32_t *obj)
{
	pcs_atomic32_fetch_and_inc(obj);
}

static inline s32 pcs_atomic32_fetch_and_dec(pcs_atomic32_t *obj)
{
	return pcs_atomic32_fetch_and_sub(obj, 1);
}

static inline void pcs_atomic32_dec(pcs_atomic32_t *obj)
{
	pcs_atomic32_fetch_and_dec(obj);
}

static inline s32 pcs_atomic32_fetch_and_and(pcs_atomic32_t *obj, s32 val)
{
	return __atomic_fetch_and(&obj->val, val, __ATOMIC_SEQ_CST);
}

static inline void pcs_atomic32_and(pcs_atomic32_t *obj, s32 val)
{
	pcs_atomic32_fetch_and_and(obj, val);
}

static inline s32 pcs_atomic32_fetch_and_or(pcs_atomic32_t *obj, s32 val)
{
	return __atomic_fetch_or(&obj->val, val, __ATOMIC_SEQ_CST);
}

static inline void pcs_atomic32_or(pcs_atomic32_t *obj, s32 val)
{
	pcs_atomic32_fetch_and_or(obj, val);
}

static inline s32 pcs_atomic32_fetch_and_xor(pcs_atomic32_t *obj, s32 val)
{
	return __atomic_fetch_xor(&obj->val, val, __ATOMIC_SEQ_CST);
}

static inline void pcs_atomic32_xor(pcs_atomic32_t *obj, s32 val)
{
	pcs_atomic32_fetch_and_xor(obj, val);
}

static inline s32 pcs_atomic32_exchange(pcs_atomic32_t *obj, s32 val)
{
	return __atomic_exchange_n(&obj->val, val, __ATOMIC_SEQ_CST);
}

static inline s32 pcs_atomic32_cas(pcs_atomic32_t *obj, s32 old_val, s32 new_val)
{
	s32 tmp = old_val;
	__atomic_compare_exchange_n(&obj->val, &tmp, new_val, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
	return tmp;
}

// ===== s64 =====

static inline void pcs_atomic64_store(pcs_atomic64_t *obj, s64 val)
{
	__atomic_store_n(&obj->val, val, __ATOMIC_RELAXED);
}

static inline s64 pcs_atomic64_load(pcs_atomic64_t *obj)
{
	return __atomic_load_n(&obj->val, __ATOMIC_RELAXED);
}

static inline s64 pcs_atomic64_fetch_and_add(pcs_atomic64_t *obj, s64 val)
{
	return __atomic_fetch_add(&obj->val, val, __ATOMIC_SEQ_CST);
}

static inline void pcs_atomic64_add(pcs_atomic64_t *obj, s64 val)
{
	pcs_atomic64_fetch_and_add(obj, val);
}

static inline s64 pcs_atomic64_fetch_and_sub(pcs_atomic64_t *obj, s64 val)
{
	return __atomic_fetch_sub(&obj->val, val, __ATOMIC_SEQ_CST);
}

static inline void pcs_atomic64_sub(pcs_atomic64_t *obj, s64 val)
{
	pcs_atomic64_fetch_and_sub(obj, val);
}

static inline s64 pcs_atomic64_fetch_and_inc(pcs_atomic64_t *obj)
{
	return pcs_atomic64_fetch_and_add(obj, 1);
}

static inline void pcs_atomic64_inc(pcs_atomic64_t *obj)
{
	pcs_atomic64_fetch_and_inc(obj);
}

static inline s64 pcs_atomic64_fetch_and_dec(pcs_atomic64_t *obj)
{
	return pcs_atomic64_fetch_and_sub(obj, 1);
}

static inline void pcs_atomic64_dec(pcs_atomic64_t *obj)
{
	pcs_atomic64_fetch_and_dec(obj);
}

static inline s64 pcs_atomic64_fetch_and_and(pcs_atomic64_t *obj, s64 val)
{
	return __atomic_fetch_and(&obj->val, val, __ATOMIC_SEQ_CST);
}

static inline void pcs_atomic64_and(pcs_atomic64_t *obj, s64 val)
{
	pcs_atomic64_fetch_and_and(obj, val);
}

static inline s64 pcs_atomic64_fetch_and_or(pcs_atomic64_t *obj, s64 val)
{
	return __atomic_fetch_or(&obj->val, val, __ATOMIC_SEQ_CST);
}

static inline void pcs_atomic64_or(pcs_atomic64_t *obj, s64 val)
{
	pcs_atomic64_fetch_and_or(obj, val);
}

static inline s64 pcs_atomic64_fetch_and_xor(pcs_atomic64_t *obj, s64 val)
{
	return __atomic_fetch_xor(&obj->val, val, __ATOMIC_SEQ_CST);
}

static inline void pcs_atomic64_xor(pcs_atomic64_t *obj, s64 val)
{
	pcs_atomic64_fetch_and_xor(obj, val);
}

static inline s64 pcs_atomic64_exchange(pcs_atomic64_t *obj, s64 val)
{
	return __atomic_exchange_n(&obj->val, val, __ATOMIC_SEQ_CST);
}

static inline s64 pcs_atomic64_cas(pcs_atomic64_t *obj, s64 old_val, s64 new_val)
{
	s64 tmp = old_val;
	__atomic_compare_exchange_n(&obj->val, &tmp, new_val, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
	return tmp;
}

// ===== ptr =====

static inline void pcs_atomic_uptr_store(pcs_atomic_ptr_t *obj, ULONG_PTR val)
{
	__atomic_store_n(&obj->val, val, __ATOMIC_RELAXED);
}

static inline ULONG_PTR pcs_atomic_uptr_load(pcs_atomic_ptr_t *obj)
{
	return __atomic_load_n(&obj->val, __ATOMIC_RELAXED);
}

static inline ULONG_PTR pcs_atomic_uptr_fetch_and_and(pcs_atomic_ptr_t *obj, ULONG_PTR val)
{
	return __atomic_fetch_and(&obj->val, val, __ATOMIC_SEQ_CST);
}

static inline void pcs_atomic_uptr_and(pcs_atomic_ptr_t *obj, ULONG_PTR val)
{
	pcs_atomic_uptr_fetch_and_and(obj, val);
}

static inline ULONG_PTR pcs_atomic_uptr_fetch_and_or(pcs_atomic_ptr_t *obj, ULONG_PTR val)
{
	return __atomic_fetch_or(&obj->val, val, __ATOMIC_SEQ_CST);
}

static inline void pcs_atomic_uptr_or(pcs_atomic_ptr_t *obj, ULONG_PTR val)
{
	pcs_atomic_uptr_fetch_and_or(obj, val);
}

static inline ULONG_PTR pcs_atomic_uptr_fetch_and_xor(pcs_atomic_ptr_t *obj, ULONG_PTR val)
{
	return __atomic_fetch_xor(&obj->val, val, __ATOMIC_SEQ_CST);
}

static inline void pcs_atomic_uptr_xor(pcs_atomic_ptr_t *obj, ULONG_PTR val)
{
	pcs_atomic_uptr_fetch_and_xor(obj, val);
}

static inline ULONG_PTR pcs_atomic_uptr_exchange(pcs_atomic_ptr_t *obj, ULONG_PTR val)
{
	return __atomic_exchange_n(&obj->val, val, __ATOMIC_SEQ_CST);
}

static inline ULONG_PTR pcs_atomic_uptr_cas(pcs_atomic_ptr_t *obj, ULONG_PTR old_val, ULONG_PTR new_val)
{
	ULONG_PTR tmp = old_val;
	__atomic_compare_exchange_n(&obj->val, &tmp, new_val, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
	return tmp;
}

/* barriers */

static inline void pcs_compiler_mb(void)
{
	__atomic_signal_fence(__ATOMIC_SEQ_CST);
}

static inline void pcs_rmb(void)
{
	__atomic_thread_fence(__ATOMIC_ACQUIRE);
}

static inline void pcs_wmb(void)
{
	__atomic_thread_fence(__ATOMIC_RELEASE);
}

static inline void pcs_mb(void)
{
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
}
