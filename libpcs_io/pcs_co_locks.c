/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "log.h"
#include "pcs_co_locks.h"
#include "pcs_context.h"
#include "pcs_process.h"

#ifndef __WINDOWS__
#include <errno.h>
#endif

/* We could put pthread_mutex_t into each of pcs_co_mutex, pcs_co_rwlock, pcs_co_sem,
 * but such design has signifcant downsides:
 *
 * 1. User has to call fini() function for each synchronization object.
 * 2. Synchronization objects take more memory.
 * 3. Synchronization objects can consume OS handles event when not in use.
 *
 * If pthread_mutex_t is implemented using futex, all above points are not signifcant.
 * Nevertheless, we do not want to create separate implementations of synchronization
 * objects for different operating systems. */

/* Any large enough prime number can be used */
#define NR_STATIC_MTX	251

#define STATIC_MTX_X1	{.mtx = PTHREAD_MUTEX_INITIALIZER}
#define STATIC_MTX_X2	STATIC_MTX_X1, STATIC_MTX_X1
#define STATIC_MTX_X4	STATIC_MTX_X2, STATIC_MTX_X2
#define STATIC_MTX_X8	STATIC_MTX_X4, STATIC_MTX_X4
#define STATIC_MTX_X16	STATIC_MTX_X8, STATIC_MTX_X8
#define STATIC_MTX_X32	STATIC_MTX_X16, STATIC_MTX_X16
#define STATIC_MTX_X64	STATIC_MTX_X32, STATIC_MTX_X32
#define STATIC_MTX_X128	STATIC_MTX_X64, STATIC_MTX_X64

union {
	pthread_mutex_t mtx;
	u8 pad[64];
} static_mtx[NR_STATIC_MTX] = {
	STATIC_MTX_X128,
	STATIC_MTX_X64,
	STATIC_MTX_X32,
	STATIC_MTX_X16,
	STATIC_MTX_X8,
	STATIC_MTX_X2,
	STATIC_MTX_X1,
};

static pthread_mutex_t *lock_static_mtx(void *p)
{
	pthread_mutex_t *mtx = &static_mtx[(ULONG_PTR)p % NR_STATIC_MTX].mtx;
	pthread_mutex_lock(mtx);
	return mtx;
}

static struct pcs_coroutine *pcs_co_waitqueue_dequeue(struct pcs_co_waitqueue *wq)
{
	if (likely(cd_list_empty(&wq->waiters)))
		return NULL;

	struct pcs_coroutine * co = cd_list_first_entry(&wq->waiters, struct pcs_coroutine, wait_list);
	cd_list_del_init(&co->wait_list);
	return co;
}

void pcs_co_waitqueue_wakeup_one(struct pcs_co_waitqueue *wq)
{
	struct pcs_coroutine *co = pcs_co_waitqueue_dequeue(wq);
	if (co)
		pcs_co_wakeup(co);
}

void pcs_co_waitqueue_wakeup_all(struct pcs_co_waitqueue *wq)
{
	for (;;) {
		struct pcs_coroutine *co = pcs_co_waitqueue_dequeue(wq);
		if (!co)
			break;

		pcs_co_wakeup(co);
	}
}

void pcs_co_event_signal(struct pcs_co_event *ev)
{
	/* Transition A->C, B->C */
	ULONG_PTR val = pcs_atomic_uptr_exchange(&ev->val, PCS_CO_EVENT_SIGNALED);
	if (val > PCS_CO_EVENT_SIGNALED)
		pcs_co_wakeup_waiting((struct pcs_coroutine *)val);
}

static void __pcs_co_event_timer(void *data)
{
	struct pcs_co_event *ev = data;

	ULONG_PTR val = pcs_atomic_uptr_load(&ev->val);
	while (val > PCS_CO_EVENT_SIGNALED) {
		/* Transition B->A */
		ULONG_PTR res = pcs_atomic_uptr_cas(&ev->val, val, 0);
		if (res == val) {
			pcs_co_wakeup_waiting((struct pcs_coroutine *)val);
			break;
		}
		val = res;
	}
}

int pcs_co_event_wait_timeout(struct pcs_co_event *ev, int *timeout)
{
	ULONG_PTR val = pcs_atomic_uptr_load(&ev->val);
	BUG_ON(val > PCS_CO_EVENT_SIGNALED);
	if (val)
		return 0;

	struct pcs_evloop *evloop = pcs_current_evloop;

	if (likely(!timeout)) {
		evloop->wait_on = ev;
		pcs_co_schedule();
		return 0;
	}

	if (unlikely(*timeout == 0))
		return -PCS_CO_TIMEDOUT;

	abs_time_t wait_start = evloop->last_abs_time_ms;
	struct pcs_timer timer;
	init_timer(evloop->proc, &timer, __pcs_co_event_timer, ev);
	mod_timer(&timer, *timeout);
	evloop->wait_on = ev;
	pcs_co_schedule();
	del_timer_sync(&timer);

	val = pcs_atomic_uptr_load(&ev->val);
	BUG_ON(val > PCS_CO_EVENT_SIGNALED);
	if (!val) {
		*timeout = 0;
		return -PCS_CO_TIMEDOUT;
	}

	time_diff_t delay = get_elapsed_time(evloop->last_abs_time_ms, wait_start);
	if (delay >= *timeout)
		*timeout = 0;
	else
		*timeout -= (int)delay;
	return 0;
}

struct wait_item {
	struct cd_list		lst;
	struct pcs_coroutine	*co;
	void			*lock;
	ULONG_PTR		(*get_holder)(void *data);
	struct pcs_co_event	*event;
	struct pcs_timer	timer;
};

ULONG_PTR __pcs_co_mutex_get_holder(void *lock)
{
	struct pcs_co_mutex *mutex = lock;
	return pcs_atomic_uptr_load(&mutex->val) & ~PCS_CO_MUTEX_HAS_WAITERS;
}

ULONG_PTR __pcs_co_rwlock_get_holder(void *lock)
{
	struct pcs_co_rwlock *rwlock = lock;
	ULONG_PTR val = pcs_atomic_uptr_load(&rwlock->val);
	if (!(val & PCS_CO_RWLOCK_WRITE_LOCKED)) {
		/* read lockers are not tracked because of perfomance impact on fast path */
		return 0;
	}

	return val & ~(PCS_CO_RWLOCK_WRITE_LOCKED | PCS_CO_MUTEX_HAS_WAITERS);
}

ULONG_PTR __pcs_co_sem_get_holder(void *lock)
{
	/* semaphore does not belong to any particular coroutine */
	return 0;
}

#if PCS_CO_LOCK_TIMEOUT
static void __pcs_co_lock_timer(void *data)
{
	struct wait_item *w = data;
	struct pcs_coroutine *co = w->co;
	struct pcs_process *proc = co->proc;

	pthread_mutex_lock(&proc->co_list_mutex);
	pthread_mutex_t *mtx = lock_static_mtx(w->lock);
	if (cd_list_empty(&w->lst)) {
		pthread_mutex_unlock(mtx);
		pthread_mutex_unlock(&proc->co_list_mutex);
		return;
	}

	struct pcs_coroutine *holder = (struct pcs_coroutine *)w->get_holder(w->lock);
	if (holder) {
		pcs_log(LOG_ERR, "Deadlock waiting for lock co=%s(%p), holder=%s(%p) state=%#x",
			co->name ? co->name : "", co,
			holder->name ? holder->name : "", holder, pcs_atomic32_load(&holder->state));
		pcs_co_bt_one(co);
		pcs_co_bt_one(holder);
	} else {
		pcs_log(LOG_ERR, "Deadlock waiting for lock co=%s(%p)", co->name ? co->name : "", co);
		pcs_co_bt_one(co);
	}

#ifdef COROUTINE_ABORT_ON_MUTEX_TIMEOUT
	BUG();
#else
	pthread_mutex_unlock(mtx);
	pthread_mutex_unlock(&proc->co_list_mutex);

	mod_timer(&w->timer, PCS_CO_LOCK_TIMEOUT);
#endif
}
#endif

static int lock_wait(struct wait_item *w, int *timeout)
{
#if PCS_CO_LOCK_TIMEOUT
	if (!timeout || *timeout > PCS_CO_LOCK_TIMEOUT) {
		init_timer(w->co->proc, &w->timer, __pcs_co_lock_timer, w);
		mod_timer(&w->timer, PCS_CO_LOCK_TIMEOUT);
		int rc = pcs_co_event_wait_timeout(w->event, timeout);
		del_timer_sync(&w->timer);
		return rc;
	}
#endif
	return pcs_co_event_wait_timeout(w->event, timeout);
}

void pcs_co_mutex_lock(struct pcs_co_mutex *mutex)
{
	struct pcs_coroutine *co = pcs_current_co;
	BUG_ON(!co);

	ULONG_PTR self = (ULONG_PTR)co;

	/* Transition A->B */
	if (likely(pcs_atomic_uptr_cas(&mutex->val, 0, self) == 0))
		return;

	pthread_mutex_t *mtx = lock_static_mtx(mutex);

	ULONG_PTR val = pcs_atomic_uptr_load(&mutex->val);
	for (;;) {
		if (val == 0) {
			/* Transition A->B */
			if ((val = pcs_atomic_uptr_cas(&mutex->val, 0, self)) != 0)
				continue;

			pthread_mutex_unlock(mtx);
			return;
		}

		if (val & PCS_CO_MUTEX_HAS_WAITERS)
			break;

		/* Transition B->C */
		ULONG_PTR res = pcs_atomic_uptr_cas(&mutex->val, val, val | PCS_CO_MUTEX_HAS_WAITERS);
		if (res == val)
			break;

		val = res;
	}

	BUG_ON((val & ~PCS_CO_MUTEX_HAS_WAITERS) == self);

	struct pcs_co_event ev;
	pcs_co_event_init(&ev);
	struct wait_item w = {.co = co, .event = &ev, .lock = mutex, .get_holder = __pcs_co_mutex_get_holder};
	cd_list_add_tail(&w.lst, &mutex->waiters);
	pthread_mutex_unlock(mtx);

	lock_wait(&w, NULL);
	BUG_ON(!cd_list_empty(&w.lst));
}

int pcs_co_mutex_trylock(struct pcs_co_mutex *mutex)
{
	struct pcs_coroutine *co = pcs_current_co;
	BUG_ON(!co);

	ULONG_PTR self = (ULONG_PTR)co;

	/* Transition A->B */
	if (likely(pcs_atomic_uptr_cas(&mutex->val, 0, self) == 0))
		return 0;

	return -PCS_CO_WOULDBLOCK;
}

int pcs_co_mutex_lock_cancelable(struct pcs_co_mutex *mutex)
{
	struct pcs_coroutine *co = pcs_current_co;
	BUG_ON(!co);

	ULONG_PTR self = (ULONG_PTR)co;

	/* Transition A->B */
	if (likely(pcs_atomic_uptr_cas(&mutex->val, 0, self) == 0))
		return 0;

	int rc;
	if ((rc = pcs_cancelable_prepare_wait(&co->io_wait, co->ctx)))
		return rc;

	pthread_mutex_t *mtx = lock_static_mtx(mutex);

	ULONG_PTR val = pcs_atomic_uptr_load(&mutex->val);
	for (;;) {
		if (val == 0) {
			/* Transition A->B */
			if ((val = pcs_atomic_uptr_cas(&mutex->val, 0, self)) != 0)
				continue;

			pthread_mutex_unlock(mtx);
			return 0;
		}

		if (val & PCS_CO_MUTEX_HAS_WAITERS)
			break;

		/* Transition B->C */
		ULONG_PTR res = pcs_atomic_uptr_cas(&mutex->val, val, val | PCS_CO_MUTEX_HAS_WAITERS);
		if (res == val)
			break;

		val = res;
	}

	BUG_ON((val & ~PCS_CO_MUTEX_HAS_WAITERS) == self);

	struct wait_item w = {.co = co, .event = &co->io_wait.ev, .lock = mutex, .get_holder = __pcs_co_mutex_get_holder};
	cd_list_add_tail(&w.lst, &mutex->waiters);
	pthread_mutex_unlock(mtx);

	lock_wait(&w, NULL);

	pthread_mutex_lock(mtx);
	if (cd_list_empty(&w.lst)) {
		pthread_mutex_unlock(mtx);
		return 0;
	}

	cd_list_del(&w.lst);
	if (cd_list_empty(&mutex->waiters)) {
		/* Transition C->B */
		pcs_atomic_uptr_and(&mutex->val, ~PCS_CO_MUTEX_HAS_WAITERS);
	}

	pthread_mutex_unlock(mtx);
	rc = pcs_context_is_canceled(co->ctx);
	BUG_ON(!rc);
	return rc;
}

void pcs_co_mutex_unlock(struct pcs_co_mutex *mutex)
{
	struct pcs_coroutine *co = pcs_current_co;
	BUG_ON(!co);

	ULONG_PTR self = (ULONG_PTR)co;

	/* Transition B->A */
	ULONG_PTR val = pcs_atomic_uptr_cas(&mutex->val, self, 0);
	if (likely(val == self))
		return;

	BUG_ON(val != (self | PCS_CO_MUTEX_HAS_WAITERS));

	pthread_mutex_t *mtx = lock_static_mtx(mutex);

	BUG_ON(cd_list_empty(&mutex->waiters));
	struct wait_item *w = cd_list_first_entry(&mutex->waiters, struct wait_item, lst);
	cd_list_del_init(&w->lst);

	ULONG_PTR new_val = (ULONG_PTR)w->co;
	if (!cd_list_empty(&mutex->waiters))
		new_val |= PCS_CO_MUTEX_HAS_WAITERS;

	/* Transition C->B or C->C */
	ULONG_PTR res = pcs_atomic_uptr_exchange(&mutex->val, new_val);
	BUG_ON(res != val);

	pcs_co_event_signal(w->event);
	pthread_mutex_unlock(mtx);
}

/* Returns 0 on success, current value of lock->val otherwise */
ULONG_PTR __pcs_co_read_trylock(struct pcs_co_rwlock *lock)
{
	ULONG_PTR val = pcs_atomic_uptr_load(&lock->val);

	for (;;) {
		if (unlikely((val & (PCS_CO_RWLOCK_WRITE_LOCKED | PCS_CO_RWLOCK_HAS_WAITERS)) != 0)) {
			/* RW-lock is locked for write or has write waiters,
			 * have to put current coroutine into read waiters queue */
			return val;
		}

		/* Transition A->C or C->C */
		ULONG_PTR res = pcs_atomic_uptr_cas(&lock->val, val, val + (1 << PCS_CO_RWLOCK_NR_READERS_SHIFT));
		if (likely(res == val))
			return 0;

		val = res;
	}
}

void pcs_co_read_lock(struct pcs_co_rwlock *lock)
{
	struct pcs_coroutine *co = pcs_current_co;
	BUG_ON(!co);

	if (likely(__pcs_co_read_trylock(lock) == 0))
		return;

	pthread_mutex_t *mtx = lock_static_mtx(lock);

	ULONG_PTR val;
	for (;;) {
		if ((val = __pcs_co_read_trylock(lock)) == 0) {
			pthread_mutex_unlock(mtx);
			return;
		}

		if (val & PCS_CO_RWLOCK_HAS_WAITERS)
			break;

		/* Transition B->D */
		ULONG_PTR res = pcs_atomic_uptr_cas(&lock->val, val, val | PCS_CO_RWLOCK_HAS_WAITERS);
		if (res == val)
			break;
	}

	struct pcs_co_event ev;
	pcs_co_event_init(&ev);
	struct wait_item w = {.co = co, .event = &ev, .lock = lock, .get_holder = __pcs_co_rwlock_get_holder};
	cd_list_add_tail(&w.lst, &lock->rwaiters);
	pthread_mutex_unlock(mtx);

	lock_wait(&w, NULL);
	BUG_ON(!cd_list_empty(&w.lst));
}

void pcs_co_write_lock(struct pcs_co_rwlock *lock)
{
	struct pcs_coroutine *co = pcs_current_co;
	BUG_ON(!co);

	ULONG_PTR self = (ULONG_PTR)co | PCS_CO_RWLOCK_WRITE_LOCKED;

	/* Transition A->B */
	if (likely(pcs_atomic_uptr_cas(&lock->val, 0, self) == 0))
		return;

	pthread_mutex_t *mtx = lock_static_mtx(lock);

	ULONG_PTR val = pcs_atomic_uptr_load(&lock->val);
	for (;;) {
		if (val == 0) {
			/* Transition A->B */
			if ((val = pcs_atomic_uptr_cas(&lock->val, 0, self)) != 0)
				continue;

			pthread_mutex_unlock(mtx);
			return;
		}

		if (val & PCS_CO_RWLOCK_HAS_WAITERS)
			break;

		/* Transition B->D or C->E */
		ULONG_PTR res = pcs_atomic_uptr_cas(&lock->val, val, val | PCS_CO_RWLOCK_HAS_WAITERS);
		if (res == val)
			break;

		val = res;
	}

	BUG_ON((val & ~PCS_CO_RWLOCK_HAS_WAITERS) == self);

	struct pcs_co_event ev;
	pcs_co_event_init(&ev);
	struct wait_item w = {.co = co, .event = &ev, .lock = lock, .get_holder = __pcs_co_rwlock_get_holder};
	cd_list_add_tail(&w.lst, &lock->wwaiters);
	pthread_mutex_unlock(mtx);

	lock_wait(&w, NULL);
	BUG_ON(!cd_list_empty(&w.lst));
}

int pcs_co_read_trylock(struct pcs_co_rwlock *lock)
{
	struct pcs_coroutine *co = pcs_current_co;
	BUG_ON(!co);

	if (likely(__pcs_co_read_trylock(lock) == 0))
		return 0;

	return -PCS_CO_WOULDBLOCK;
}

int pcs_co_write_trylock(struct pcs_co_rwlock *lock)
{
	struct pcs_coroutine *co = pcs_current_co;
	BUG_ON(!co);

	ULONG_PTR self = (ULONG_PTR)co | PCS_CO_RWLOCK_WRITE_LOCKED;

	/* Transition A->B */
	if (likely(pcs_atomic_uptr_cas(&lock->val, 0, self) == 0))
		return 0;

	return -PCS_CO_WOULDBLOCK;
}

int pcs_co_read_lock_cancelable(struct pcs_co_rwlock *lock)
{
	struct pcs_coroutine *co = pcs_current_co;
	BUG_ON(!co);

	if (likely(__pcs_co_read_trylock(lock) == 0))
		return 0;

	int rc;
	if ((rc = pcs_cancelable_prepare_wait(&co->io_wait, co->ctx)))
		return rc;

	pthread_mutex_t *mtx = lock_static_mtx(lock);

	ULONG_PTR val;
	for (;;) {
		if ((val = __pcs_co_read_trylock(lock)) == 0) {
			pthread_mutex_unlock(mtx);
			return 0;
		}

		if (val & PCS_CO_RWLOCK_HAS_WAITERS)
			break;

		/* Transition B->D */
		ULONG_PTR res = pcs_atomic_uptr_cas(&lock->val, val, val | PCS_CO_RWLOCK_HAS_WAITERS);
		if (res == val)
			break;
	}

	struct wait_item w = {.co = co, .event = &co->io_wait.ev, .lock = lock, .get_holder = __pcs_co_rwlock_get_holder};
	cd_list_add_tail(&w.lst, &lock->rwaiters);
	pthread_mutex_unlock(mtx);

	lock_wait(&w, NULL);

	pthread_mutex_lock(mtx);
	if (cd_list_empty(&w.lst)) {
		pthread_mutex_unlock(mtx);
		return 0;
	}

	cd_list_del(&w.lst);
	if (cd_list_empty(&lock->wwaiters) && cd_list_empty(&lock->rwaiters)) {
		/* Transition D->B */
		pcs_atomic_uptr_and(&lock->val, ~PCS_CO_RWLOCK_HAS_WAITERS);
	}

	pthread_mutex_unlock(mtx);
	rc = pcs_context_is_canceled(co->ctx);
	BUG_ON(!rc);
	return rc;
}

int pcs_co_write_lock_cancelable(struct pcs_co_rwlock *lock)
{
	struct pcs_coroutine *co = pcs_current_co;
	BUG_ON(!co);

	ULONG_PTR self = (ULONG_PTR)co | PCS_CO_RWLOCK_WRITE_LOCKED;

	/* Transition A->B */
	if (likely(pcs_atomic_uptr_cas(&lock->val, 0, self) == 0))
		return 0;

	int rc;
	if ((rc = pcs_cancelable_prepare_wait(&co->io_wait, co->ctx)))
		return rc;

	pthread_mutex_t *mtx = lock_static_mtx(lock);

	ULONG_PTR val = pcs_atomic_uptr_load(&lock->val);
	for (;;) {
		if (val == 0) {
			/* Transition A->B */
			if ((val = pcs_atomic_uptr_cas(&lock->val, 0, self)) != 0)
				continue;

			pthread_mutex_unlock(mtx);
			return 0;
		}

		if (val & PCS_CO_RWLOCK_HAS_WAITERS)
			break;

		/* Transition B->D or C->E */
		ULONG_PTR res = pcs_atomic_uptr_cas(&lock->val, val, val | PCS_CO_RWLOCK_HAS_WAITERS);
		if (res == val)
			break;

		val = res;
	}

	BUG_ON((val & ~PCS_CO_RWLOCK_HAS_WAITERS) == self);

	struct wait_item w = {.co = co, .event = &co->io_wait.ev, .lock = lock, .get_holder = __pcs_co_rwlock_get_holder};
	cd_list_add_tail(&w.lst, &lock->wwaiters);
	pthread_mutex_unlock(mtx);

	lock_wait(&w, NULL);

	pthread_mutex_lock(mtx);
	if (cd_list_empty(&w.lst)) {
		pthread_mutex_unlock(mtx);
		return 0;
	}

	cd_list_del(&w.lst);
	if (cd_list_empty(&lock->wwaiters) && cd_list_empty(&lock->rwaiters)) {
		/* Transition D->B or E->C */
		pcs_atomic_uptr_and(&lock->val, ~PCS_CO_RWLOCK_HAS_WAITERS);
	}

	pthread_mutex_unlock(mtx);
	rc = pcs_context_is_canceled(co->ctx);
	BUG_ON(!rc);
	return rc;
}

/* Handoff RW-lock ownerwhip to selected coroutine */
static void __pcs_co_read_unlock_writer(struct pcs_co_rwlock *lock, ULONG_PTR val, struct pcs_coroutine *co)
{
	ULONG_PTR new_val = (ULONG_PTR)co | PCS_CO_RWLOCK_WRITE_LOCKED;
	if (!cd_list_empty(&lock->wwaiters) || !cd_list_empty(&lock->rwaiters))
		new_val |= PCS_CO_RWLOCK_HAS_WAITERS;

	ULONG_PTR res = pcs_atomic_uptr_exchange(&lock->val, new_val);
	BUG_ON(res != val);
}

void pcs_co_read_unlock(struct pcs_co_rwlock *lock)
{
	struct pcs_coroutine *co = pcs_current_co;
	BUG_ON(!co);

	ULONG_PTR val = pcs_atomic_uptr_load(&lock->val);
	for (;;) {
		if (unlikely(val == ((1 << PCS_CO_RWLOCK_NR_READERS_SHIFT) | PCS_CO_RWLOCK_HAS_WAITERS)))
			break;

		BUG_ON(val & PCS_CO_RWLOCK_WRITE_LOCKED);
		BUG_ON(val < (1 << PCS_CO_RWLOCK_NR_READERS_SHIFT));

		/* Transition C->A, C->C or E->E */
		ULONG_PTR res = pcs_atomic_uptr_cas(&lock->val, val, val - (1 << PCS_CO_RWLOCK_NR_READERS_SHIFT));
		if (res == val)
			return;

		val = res;
	}

	pthread_mutex_t *mtx = lock_static_mtx(lock);

	BUG_ON(cd_list_empty(&lock->wwaiters));
	struct wait_item *w = cd_list_first_entry(&lock->wwaiters, struct wait_item, lst);
	cd_list_del_init(&w->lst);

	/* Transition E->B or E->D */
	__pcs_co_read_unlock_writer(lock, val, w->co);
	pcs_co_event_signal(w->event);
	pthread_mutex_unlock(mtx);
}

void pcs_co_write_unlock(struct pcs_co_rwlock *lock)
{
	struct pcs_coroutine *co = pcs_current_co;
	BUG_ON(!co);

	ULONG_PTR self = (ULONG_PTR)co | PCS_CO_RWLOCK_WRITE_LOCKED;

	/* Transition B->A */
	ULONG_PTR val = pcs_atomic_uptr_cas(&lock->val, self, 0);
	if (likely(val == self))
		return;

	BUG_ON(val != (self | PCS_CO_RWLOCK_HAS_WAITERS));

	pthread_mutex_t *mtx = lock_static_mtx(lock);

	if (!cd_list_empty(&lock->wwaiters)) {
		struct wait_item *w = cd_list_first_entry(&lock->wwaiters, struct wait_item, lst);
		cd_list_del_init(&w->lst);

		/* Transition D->B or D->D */
		__pcs_co_read_unlock_writer(lock, val, w->co);
		pcs_co_event_signal(w->event);
		pthread_mutex_unlock(mtx);
		return;
	}

	ULONG_PTR nr_rwaiters = 0;
	struct wait_item *w;
	cd_list_for_each_entry(struct wait_item, w, &lock->rwaiters, lst)
		nr_rwaiters++;
	BUG_ON(!nr_rwaiters);

	/* Transition D->C */
	ULONG_PTR res = pcs_atomic_uptr_exchange(&lock->val, nr_rwaiters << PCS_CO_RWLOCK_NR_READERS_SHIFT);
	BUG_ON(res != val);

	while (!cd_list_empty(&lock->rwaiters)) {
		struct wait_item *w = cd_list_first_entry(&lock->rwaiters, struct wait_item, lst);
		cd_list_del_init(&w->lst);
		pcs_co_event_signal(w->event);
	}

	pthread_mutex_unlock(mtx);
}

void pcs_co_cond_signal(struct pcs_co_cond *cond)
{
	BUG_ON(!pcs_in_evloop());

	if (cd_list_empty(&cond->waiters))	/* Is it safe without mutex? */
		return;

	pthread_mutex_t *mtx = lock_static_mtx(cond);

	if (!cd_list_empty(&cond->waiters)) {
		struct wait_item *w = cd_list_first_entry(&cond->waiters, struct wait_item, lst);
		cd_list_del_init(&w->lst);
		pcs_co_event_signal(w->event);
	}

	pthread_mutex_unlock(mtx);
}

void pcs_co_cond_broadcast(struct pcs_co_cond *cond)
{
	BUG_ON(!pcs_in_evloop());

	pthread_mutex_t *mtx = lock_static_mtx(cond);

	while (!cd_list_empty(&cond->waiters)) {
		struct wait_item *w = cd_list_first_entry(&cond->waiters, struct wait_item, lst);
		cd_list_del_init(&w->lst);
		pcs_co_event_signal(w->event);
	}

	pthread_mutex_unlock(mtx);
}

int pcs_co_cond_wait_timeout(struct pcs_co_cond *cond, int *timeout)
{
	struct pcs_coroutine *co = pcs_current_co;
	BUG_ON(!co);

	pthread_mutex_t *mtx = lock_static_mtx(cond);
	struct pcs_co_event ev;
	pcs_co_event_init(&ev);
	struct wait_item w = {.co = co, .event = &ev, .lock = cond};
	cd_list_add_tail(&w.lst, &cond->waiters);
	pthread_mutex_unlock(mtx);

	cond->unlock_fn(cond->lock);
	int rc = pcs_co_event_wait_timeout(&ev, timeout);
	cond->lock_fn(cond->lock);

	if (!rc) {
		BUG_ON(!cd_list_empty(&w.lst));
		return 0;
	}

	pthread_mutex_lock(mtx);
	if (cd_list_empty(&w.lst)) {
		pthread_mutex_unlock(mtx);
		return 0;
	}
	cd_list_del(&w.lst);
	pthread_mutex_unlock(mtx);
	return rc;
}

int pcs_co_cond_wait_cancelable(struct pcs_co_cond *cond)
{
	struct pcs_coroutine *co = pcs_current_co;
	BUG_ON(!co);

	int rc;
	if ((rc = pcs_cancelable_prepare_wait(&co->io_wait, co->ctx)))
		return rc;

	pthread_mutex_t *mtx = lock_static_mtx(cond);
	struct wait_item w = {.co = co, .event = &co->io_wait.ev, .lock = cond};
	cd_list_add_tail(&w.lst, &cond->waiters);
	pthread_mutex_unlock(mtx);

	cond->unlock_fn(cond->lock);
	pcs_co_event_wait(&co->io_wait.ev);
	cond->lock_fn(cond->lock);

	pthread_mutex_lock(mtx);
	if (cd_list_empty(&w.lst)) {
		pthread_mutex_unlock(mtx);
		return 0;
	}
	cd_list_del(&w.lst);
	pthread_mutex_unlock(mtx);
	rc = pcs_context_is_canceled(co->ctx);
	BUG_ON(!rc);
	return rc;
}

/* Returns 1 on success, 0 otherwise */
static int __pcs_co_sem_tryget(struct pcs_co_sem *sem)
{
	s32 val = pcs_atomic32_load(&sem->val);
	for (;;) {
		if (unlikely(val <= 0))
			return 0;

		/* Transition A->A */
		s32 res = pcs_atomic32_cas(&sem->val, val, val - 1);
		if (likely(res == val))
			return 1;

		val = res;
	}
}

int pcs_co_sem_get_timeout(struct pcs_co_sem *sem, int *timeout)
{
	struct pcs_coroutine *co = pcs_current_co;
	BUG_ON(!co);

	if (likely(__pcs_co_sem_tryget(sem)))
		return 0;

	if (unlikely(timeout && *timeout == 0))
		return -PCS_CO_TIMEDOUT;

	pthread_mutex_t *mtx = lock_static_mtx(sem);

	/* Transition A->A or A->B */
	s32 val = pcs_atomic32_fetch_and_dec(&sem->val);
	if (val > 0) {
		pthread_mutex_unlock(mtx);
		return 0;
	}

	struct pcs_co_event ev;
	pcs_co_event_init(&ev);
	struct wait_item w = {.co = co, .event = &ev, .lock = sem, .get_holder = __pcs_co_sem_get_holder};
	cd_list_add_tail(&w.lst, &sem->waiters);
	pthread_mutex_unlock(mtx);

	int rc = lock_wait(&w, timeout);
	if (!rc) {
		BUG_ON(!cd_list_empty(&w.lst));
		return 0;
	}

	pthread_mutex_lock(mtx);
	if (cd_list_empty(&w.lst)) {
		pthread_mutex_unlock(mtx);
		return 0;
	}

	/* Transition B->A or B->B */
	val = pcs_atomic32_fetch_and_inc(&sem->val);
	BUG_ON(val >= 0);
	cd_list_del(&w.lst);
	pthread_mutex_unlock(mtx);
	return rc;
}

int pcs_co_sem_get_cancelable(struct pcs_co_sem *sem)
{
	struct pcs_coroutine *co = pcs_current_co;
	BUG_ON(!co);

	int rc;
	if ((rc = pcs_cancelable_prepare_wait(&co->io_wait, co->ctx)))
		return rc;

	if (likely(__pcs_co_sem_tryget(sem)))
		return 0;

	pthread_mutex_t *mtx = lock_static_mtx(sem);

	/* Transition A->A or A->B */
	s32 val = pcs_atomic32_fetch_and_dec(&sem->val);
	if (val > 0) {
		pthread_mutex_unlock(mtx);
		return 0;
	}

	struct wait_item w = {.co = co, .event = &co->io_wait.ev, .lock = sem, .get_holder = __pcs_co_sem_get_holder};
	cd_list_add_tail(&w.lst, &sem->waiters);
	pthread_mutex_unlock(mtx);

	lock_wait(&w, NULL);

	pthread_mutex_lock(mtx);
	if (cd_list_empty(&w.lst)) {
		pthread_mutex_unlock(mtx);
		return 0;
	}

	/* Transition B->A or B->B */
	val = pcs_atomic32_fetch_and_inc(&sem->val);
	BUG_ON(val >= 0);
	cd_list_del(&w.lst);
	pthread_mutex_unlock(mtx);
	rc = pcs_context_is_canceled(co->ctx);
	BUG_ON(!rc);
	return rc;
}

void pcs_co_sem_put(struct pcs_co_sem *sem)
{
	BUG_ON(!pcs_in_evloop());

	s32 val = pcs_atomic32_load(&sem->val);
	while (likely(val >= 0)) {
		/* Transition A->A */
		s32 res = pcs_atomic32_cas(&sem->val, val, val + 1);
		if (likely(res == val))
			return;
		val = res;
	}

	pthread_mutex_t *mtx = lock_static_mtx(sem);

	/* Transition A->A, B->A or B->B */
	if ((val = pcs_atomic32_fetch_and_inc(&sem->val)) >= 0) {
		pthread_mutex_unlock(mtx);
		return;
	}

	BUG_ON(cd_list_empty(&sem->waiters));
	struct wait_item *w = cd_list_first_entry(&sem->waiters, struct wait_item, lst);
	cd_list_del_init(&w->lst);
	pcs_co_event_signal(w->event);
	pthread_mutex_unlock(mtx);
}

void pcs_co_waitgroup_add(struct pcs_co_waitgroup *wg, int nr)
{
	/* Transition A->A or B->B */
	nr <<= PCS_CO_WAITGROUP_COUNTER_SHIFT;
	s32 val = pcs_atomic32_fetch_and_add(&wg->val, nr) + nr;
	if (val < 0) {
		BUG_ON(val != -1);
		pcs_co_event_signal(&wg->event);
	}
}

int pcs_co_waitgroup_wait_timeout(struct pcs_co_waitgroup *wg, int *timeout)
{
	int rc = 0;
	pcs_co_event_reset(&wg->event);

	/* Transition A->B */
	s32 val = pcs_atomic32_fetch_and_dec(&wg->val);
	BUG_ON(val & ((1 << PCS_CO_WAITGROUP_COUNTER_SHIFT) - 1));	/* double wait */
	if (val)
		rc = pcs_co_event_wait_timeout(&wg->event, timeout);

	/* Transition B->A */
	pcs_atomic32_inc(&wg->val);
	return rc;
}
