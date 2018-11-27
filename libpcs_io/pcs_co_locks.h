/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCS_CO_LOCKS_H__
#define __PCS_CO_LOCKS_H__

#include "pcs_coroutine.h"
#include "std_list.h"

#define PCS_CO_LOCK_TIMEOUT	60000

/* ----------------------------------- Waitqueue API ---------------------------------- */

/* NOTE: ugly, but struct pcs_co_waitqueue is declared in pcs_coroutine.h to avoid cyclic include */

static inline void pcs_co_waitqueue_init(struct pcs_co_waitqueue * wq)
{
	cd_list_init(&wq->waiters);
}

static inline void pcs_co_waitqueue_add(struct pcs_co_waitqueue * wq)
{
	struct pcs_coroutine * self = pcs_current_co;
	cd_list_add_tail(&self->wait_list, &wq->waiters);
}

static inline void pcs_co_waitqueue_remove(void)
{
	struct pcs_coroutine * self = pcs_current_co;
	cd_list_del_init(&self->wait_list);
}

static inline int pcs_co_waitqueue_empty(struct pcs_co_waitqueue * wq)
{
	return cd_list_empty(&wq->waiters);
}

PCS_API void pcs_co_waitqueue_wakeup_one(struct pcs_co_waitqueue * wq);
PCS_API void pcs_co_waitqueue_wakeup_all(struct pcs_co_waitqueue * wq);

/* ----------------------------------- Events API ---------------------------------- */

/* struct pcs_co_event is declared in pcs_coroutine.h */

#define PCS_CO_EVENT_SIGNALED		((ULONG_PTR)1)

/* States:
 * A. Event is not signaled, no waiter:
 *    val == 0
 *
 * B. Event is not signaled, waiter is present:
 *    val == waiter
 *
 * C. Event is signaled:
 *    val == PCS_CO_EVENT_SIGNALED
 *
 * Allowed transitions:
 *   A->B, A->C, B->A, B->C, C->A: lock-free
 */

static inline void pcs_co_event_init(struct pcs_co_event *ev)
{
	pcs_atomic_uptr_store(&ev->val, 0);
}

static inline void pcs_co_event_reset(struct pcs_co_event *ev)	/* safe to use in job/timer callback */
{
	/* Transition C->A */
	pcs_atomic_uptr_cas(&ev->val, PCS_CO_EVENT_SIGNALED, 0);
}

PCS_API void pcs_co_event_signal(struct pcs_co_event *ev);	/* safe to use in job/timer callback */
PCS_API int pcs_co_event_wait_timeout(struct pcs_co_event *ev, int *timeout);

static inline void pcs_co_event_wait(struct pcs_co_event *ev)
{
	pcs_co_event_wait_timeout(ev, NULL);
}

static inline int pcs_co_event_is_signaled(struct pcs_co_event *ev)
{
	return pcs_atomic_uptr_load(&ev->val) == PCS_CO_EVENT_SIGNALED;
}

/* ------------------------------------- Mutex API ------------------------------------- */

struct pcs_co_mutex
{
	pcs_atomic_ptr_t	val;
	struct cd_list		waiters;
};

#define PCS_CO_MUTEX_HAS_WAITERS	((ULONG_PTR)(1 << 0))

/* States:
 * A. Mutex is unlocked:
 *    val == 0
 *    waiters is empty
 *
 * B. Mutex is locked, no waiters:
 *    val == holder
 *    waiters is empty
 *
 * C. Mutex is locked, waiters are present:
 *    val == holder | PCS_CO_MUTEX_HAS_WAITERS
 *    waiters is non-empty
 *
 * Allowed transitions:
 *   A->B, B->A: lock-free
 *   B->C, C->B, C->C: under static mutex
 */

static inline void pcs_co_mutex_init(struct pcs_co_mutex *mutex)
{
	pcs_atomic_uptr_store(&mutex->val, 0);
	cd_list_init(&mutex->waiters);
}

PCS_API void pcs_co_mutex_lock(struct pcs_co_mutex *mutex);
PCS_API void pcs_co_mutex_unlock(struct pcs_co_mutex *mutex);
PCS_API int pcs_co_mutex_trylock(struct pcs_co_mutex *mutex);

static inline int pcs_co_mutex_is_locked(struct pcs_co_mutex *mutex)
{
	return pcs_atomic_uptr_load(&mutex->val) != 0;
}

/* ------------------------------------- RW-lock API ------------------------------------ */

struct pcs_co_rwlock
{
	pcs_atomic_ptr_t	val;
	struct cd_list		wwaiters;
	struct cd_list		rwaiters;
};

#define PCS_CO_RWLOCK_HAS_WAITERS	((ULONG_PTR)(1 << 0))
#define PCS_CO_RWLOCK_WRITE_LOCKED	((ULONG_PTR)(1 << 1))
#define PCS_CO_RWLOCK_NR_READERS_SHIFT	2

/* States:
 * A. RW-lock is unlocked:
 *    val == 0
 *    wwaiters is empty
 *    rwaiters is empty
 *
 * B. RW-lock is locked for write, no waiters:
 *    val == holder | PCS_CO_RWLOCK_WRITE_LOCKED
 *    wwaiters is empty
 *    rwaiters is empty
 *
 * C. RW-lock is locked for read n times, no waiters:
 *    val == n << PCS_CO_RWLOCK_NR_READERS_SHIFT
 *    wwaiters is empty
 *    rwaiters is empty
 *
 * D. RW-lock is locked for write, waiters are present:
 *    val == holder | PCS_CO_RWLOCK_WRITE_LOCKED | PCS_CO_RWLOCK_HAS_WAITERS
 *    at least one of wwaiters or rwaiters is not empty
 *
 * E. RW-lock is locked for read n times, waiters are present:
 *    val == (n << PCS_CO_RWLOCK_NR_READERS_SHIFT) | PCS_CO_RWLOCK_HAS_WAITERS
 *    wwaiters is not empty
 *
 * Allowed transitions:
 *   A->B, A->C, B->A, C->A, C->C: lock-free
 *   B->D, C->E, D->B, D->C, D->D, E->B, E->D: under static mutex
 *   E->E: lock-free if number of read locks is decremented, under static mutex otherwise
 */

static inline void pcs_co_rwlock_init(struct pcs_co_rwlock *lock)
{
	pcs_atomic_uptr_store(&lock->val, 0);
	cd_list_init(&lock->wwaiters);
	cd_list_init(&lock->rwaiters);
}

PCS_API void pcs_co_read_lock(struct pcs_co_rwlock *lock);
PCS_API void pcs_co_write_lock(struct pcs_co_rwlock *lock);
PCS_API void pcs_co_read_unlock(struct pcs_co_rwlock *lock);
PCS_API void pcs_co_write_unlock(struct pcs_co_rwlock *lock);

static inline int pcs_co_is_write_locked(struct pcs_co_rwlock *lock)
{
	return (pcs_atomic_uptr_load(&lock->val) & PCS_CO_RWLOCK_WRITE_LOCKED) != 0;
}

static inline int pcs_co_is_read_locked(struct pcs_co_rwlock *lock)
{
	ULONG_PTR val = pcs_atomic_uptr_load(&lock->val);
	return (val & PCS_CO_RWLOCK_WRITE_LOCKED) == 0 && val != 0;
}

/* -------------------------------------- Condition API ----------------------------------- */

struct pcs_co_cond
{
	void			*lock;
	void			(*lock_fn)(void *lock);
	void			(*unlock_fn)(void *lock);
	struct cd_list		waiters;
};

static inline void pcs_co_cond_init(struct pcs_co_cond *cond, struct pcs_co_mutex *mutex)
{
	cond->lock = mutex;
	cond->lock_fn = (void (*)(void *))pcs_co_mutex_lock;
	cond->unlock_fn = (void (*)(void *))pcs_co_mutex_unlock;
	cd_list_init(&cond->waiters);
}

static inline void pcs_co_cond_init_read_lock(struct pcs_co_cond *cond, struct pcs_co_rwlock *lock)
{
	cond->lock = lock;
	cond->lock_fn = (void (*)(void *))pcs_co_read_lock;
	cond->unlock_fn = (void (*)(void *))pcs_co_read_unlock;
	cd_list_init(&cond->waiters);
}

static inline void pcs_co_cond_init_write_lock(struct pcs_co_cond *cond, struct pcs_co_rwlock *lock)
{
	cond->lock = lock;
	cond->lock_fn = (void (*)(void *))pcs_co_write_lock;
	cond->unlock_fn = (void (*)(void *))pcs_co_write_unlock;
	cd_list_init(&cond->waiters);
}

PCS_API void pcs_co_cond_signal(struct pcs_co_cond *cond);	/* safe to use in job/timer callback */
PCS_API void pcs_co_cond_broadcast(struct pcs_co_cond *cond);	/* safe to use in job/timer callback */
PCS_API int pcs_co_cond_wait_timeout(struct pcs_co_cond *cond, int *timeout);
PCS_API int pcs_co_cond_wait_cancelable(struct pcs_co_cond *cond);

static inline void pcs_co_cond_wait(struct pcs_co_cond *cond)
{
	pcs_co_cond_wait_timeout(cond, NULL);
}

/* -------------------------------------- Semaphore API ----------------------------------- */

struct pcs_co_sem
{
	pcs_atomic32_t		val;
	struct cd_list		waiters;
};

/* States:
 * A. No waiters:
 *    val >= 0
 *    waiters is empty
 *
 * B. Waiters are present:
 *    val == -size(waiters)
 *    waiters is not empty
 *
 * Allowed transitions:
 *   A->A: lock-free
 *   A->B, B->A, B->B: under static mutex
 */

static inline void pcs_co_sem_init(struct pcs_co_sem *sem, unsigned int max)
{
	pcs_atomic32_store(&sem->val, max);
	cd_list_init(&sem->waiters);
}

PCS_API int pcs_co_sem_get_timeout(struct pcs_co_sem *sem, int *timeout);
PCS_API int pcs_co_sem_get_cancelable(struct pcs_co_sem *sem);
PCS_API void pcs_co_sem_put(struct pcs_co_sem *sem);		/* safe to use in job/timer callback */

static inline void pcs_co_sem_get(struct pcs_co_sem *sem)
{
	pcs_co_sem_get_timeout(sem, NULL);
}

static inline int pcs_co_sem_get_value(struct pcs_co_sem *sem)
{
	int val = pcs_atomic32_load(&sem->val);
	return val > 0 ? val : 0;
}

/* ---------------------------------- Wait Group API ---------------------------------- */

struct pcs_co_waitgroup
{
	pcs_atomic32_t		val;
	struct pcs_co_event	event;
};

#define PCS_CO_WAITGROUP_COUNTER_SHIFT	1

/* States:
 * A. No waiters:
 *    val = (nr << PCS_CO_WAITGROUP_COUNTER_SHIFT)
 *
 * B. Waiter is present:
 *    val = (nr << PCS_CO_WAITGROUP_COUNTER_SHIFT) - 1
 *
 * Allowed transitions:
 *   A->A, A->B, B->A, B->B: lock-free
 */

static inline void pcs_co_waitgroup_init(struct pcs_co_waitgroup *wg, int nr)
{
	pcs_atomic32_store(&wg->val, nr << PCS_CO_WAITGROUP_COUNTER_SHIFT);
	pcs_co_event_init(&wg->event);
}

PCS_API void pcs_co_waitgroup_add(struct pcs_co_waitgroup *wg, int nr);	/* safe to use in job/timer callback */
PCS_API int pcs_co_waitgroup_wait_timeout(struct pcs_co_waitgroup *wg, int *timeout);

static inline void pcs_co_waitgroup_done(struct pcs_co_waitgroup *wg)	/* safe to use in job/timer callback */
{
	pcs_co_waitgroup_add(wg, -1);
}

static inline void pcs_co_waitgroup_wait(struct pcs_co_waitgroup *wg)
{
	pcs_co_waitgroup_wait_timeout(wg, NULL);
}

static inline int pcs_co_waitgroup_get_value(struct pcs_co_waitgroup *wg)
{
	return (pcs_atomic32_load(&wg->val) + 1) >> PCS_CO_WAITGROUP_COUNTER_SHIFT;
}

#endif /* __PCS_CO_LOCKS_H__ */
