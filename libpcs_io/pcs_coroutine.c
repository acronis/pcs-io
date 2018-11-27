/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#if defined(__APPLE__) && !defined(_XOPEN_SOURCE)	/* needed on MacOS X for ucontext, should be the very first! */
#define _XOPEN_SOURCE 600L
#define _DARWIN_C_SOURCE
#endif

#undef _FORTIFY_SOURCE
#define _FORTIFY_SOURCE 0

#include "pcs_process.h"
#include "pcs_coroutine.h"
#include "pcs_co_locks.h"
#include "pcs_co_io.h"
#include "pcs_context.h"
#include "pcs_malloc.h"
#include "pcs_file_job.h"
#include "pcs_cpuid.h"
#include "log.h"

#ifndef __WINDOWS__
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#endif

#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef USE_VALGRIND
#include <valgrind/valgrind.h>
#endif
#ifdef PCS_ADDRESS_SANITIZER
#include <sanitizer/lsan_interface.h>
#endif

/* very perf sensetive to be in production */
#define co_log(...)	/* pcs_log(__VA_ARGS__) */

static void runqueue_put(struct pcs_co_list *runqueue, struct pcs_coroutine *co)
{
	cd_list_add_tail(&co->run_list, &runqueue->list);
	runqueue->nr++;
}

static struct pcs_coroutine *runqueue_get(struct pcs_co_list *runqueue)
{
	if (!runqueue->nr)
		return NULL;

	BUG_ON(cd_list_empty(&runqueue->list));
	struct pcs_coroutine *co = cd_list_first_entry(&runqueue->list, struct pcs_coroutine, run_list);
	cd_list_del_init(&co->run_list);
	runqueue->nr--;
	return co;
}

static void add_to_runqueue(struct pcs_evloop *evloop, struct pcs_coroutine *co)
{
	co->evloop = evloop;

	unsigned int idx = evloop->co_runqueue_cur ^ (co->sched_seq == evloop->co_sched_seq);
	struct pcs_co_list *runqueue = &evloop->co_runqueue[idx];
	runqueue_put(runqueue, co);
}

int pcs_co_find_runnable(struct pcs_evloop *evloop)
{
	return evloop->co_runqueue[0].nr || evloop->co_runqueue[1].nr;
}

static struct pcs_coroutine* get_runnable_co(struct pcs_evloop *evloop)
{
	struct pcs_co_list *runqueue = &evloop->co_runqueue[evloop->co_runqueue_cur];
	struct pcs_coroutine *co = runqueue_get(runqueue);
	if (!co)
		return NULL;

	BUG_ON(co->sched_seq == evloop->co_sched_seq);
	s32 old_state = pcs_atomic32_exchange(&co->state, CO_RUNNING);
	BUG_ON((old_state & ~CO_BACKTRACE) != CO_READY);
	if (unlikely(old_state & CO_BACKTRACE)) {
		/* Wait for backtrace to finish */
		struct pcs_process *proc = evloop->proc;
		pthread_mutex_lock(&proc->co_list_mutex);
		pthread_mutex_unlock(&proc->co_list_mutex);
	}
	return co;
}

static void pcs_co_destroy(struct pcs_coroutine * co)
{
#ifdef USE_VALGRIND
	VALGRIND_STACK_DEREGISTER(co->valgrind_stack_id);
#endif

#ifndef __WINDOWS__
	int rc = munmap(co->stack, PCS_CO_STACK_SIZE + 2 * sysconf(_SC_PAGESIZE));
	BUG_ON(rc);
#else
	DeleteFiber(co->context.fiber);
#endif
	pcs_free(co->migrate_job);
	/* de-account allocated stack size */
	pcs_alloc_account(co, -PCS_CO_STACK_SIZE);
	pcs_free(co);
}

/* Leave up to nr_max coroutines in global pool */
static void pcs_co_pool_free(struct pcs_process *proc, u32 nr_max)
{
	while (proc->co_pool.nr > nr_max) {
		BUG_ON(cd_list_empty(&proc->co_pool.list));
		struct pcs_coroutine *co = cd_list_last_entry(&proc->co_pool.list, struct pcs_coroutine, run_list);
		BUG_ON(pcs_co_state(co) != CO_ZOMBIE);
		cd_list_del(&co->list);
		cd_list_del(&co->run_list);
		proc->co_list.nr--;
		proc->co_pool.nr--;
		pcs_co_destroy(co);
	}
}

/* Place coroutine into local pool */
static void pcs_co_free(struct pcs_coroutine * co)
{
	struct pcs_evloop * evloop = pcs_current_evloop;

	BUG_ON(pcs_co_state(co) != CO_RUNNING);
	BUG_ON(!cd_list_empty(&co->run_list));
	BUG_ON(!cd_list_empty(&co->wait_list));

	pcs_atomic32_store(&co->state, CO_ZOMBIE);
	co->name = NULL;
	cd_list_add(&co->run_list, &evloop->co_pool.list);
	evloop->co_pool.nr++;
}

static void pcs_co_done(struct pcs_coroutine * co)
{
	pcs_cancelable_prepare_wait(&co->io_wait, NULL);
	pcs_context_put(co->ctx);
	co->ctx = NULL;

	pcs_co_waitqueue_wakeup_all(&co->join_wq);

	pcs_co_free(co);

	/* schedule away from zombie co. can return back if co is reused from pool */
	pcs_co_schedule();
}

void pcs_co_wakeup_waiting(struct pcs_coroutine *co)
{
	/* Preserve CO_BACKTRACE */
	s32 state = pcs_atomic32_fetch_and_xor(&co->state, CO_WAITING ^ CO_READY);
	BUG_ON((state & ~CO_BACKTRACE) != CO_WAITING);
	add_to_runqueue(pcs_current_evloop, co);
}

void pcs_co_wakeup(struct pcs_coroutine * co)
{
	switch (pcs_co_state(co)) {
	case CO_READY:
	case CO_RUNNING:
		break;

	case CO_WAITING:
		if (pcs_atomic_uptr_load(&co->io_wait.ev.val) == (ULONG_PTR)co)
			pcs_co_event_signal(&co->io_wait.ev);
		else
			pcs_co_wakeup_waiting(co);
		break;

	default:
		BUG();
	}
}

struct co_migrate_job
{
	struct pcs_file_job		job;
	struct pcs_file_job_conn	*io;
	unsigned int			hash;
	struct pcs_ucontext		context;
#ifdef PCS_ADDRESS_SANITIZER
	const void	 		*stack_bottom;
	size_t				stack_size;
#endif
};

static void pcs_co_set_current(struct pcs_coroutine *current)
{
	struct pcs_evloop *evloop = pcs_current_evloop;
	BUG_ON(current->evloop != evloop);

	evloop->co_current = current;
	pcs_current_co = current;
}

/* Switch from CO_RUNNING or CO_MIGRATED to CO_READY or CO_WAITING */
static void pcs_co_set_state(struct pcs_coroutine *co, int state)
{
	s32 old_state = pcs_atomic32_exchange(&co->state, state);
	if (unlikely(old_state & CO_BACKTRACE)) {
		pcs_log(LOG_ERR, "Dump deferred backtrace for co=%p(%s) state=%#x ctx_sw=%llu",
			co, co->name ? co->name : "", old_state, (llu)co->co_ctx_switches);
		show_trace_coroutine(&co->context);
	}
}

static void pcs_co_switch_finish(struct pcs_coroutine *current)
{
	struct pcs_evloop *evloop = pcs_current_evloop;

	// We can be called outside of evloop when finishing move_from_coroutine or from migrate_to_thread.
	// Ignore those cases.
	if (unlikely(!evloop))
		return;

	struct pcs_coroutine *co = evloop->co_current;
	if (evloop->wait_on) {
		/* We have switch away from the coroutine that called pcs_co_event_wait().
		 * Make an attempt to place coroutine into the event single-element wait queue. */
		pcs_co_set_state(co, CO_WAITING);

		/* Transition A->B */
		ULONG_PTR val = pcs_atomic_uptr_cas(&evloop->wait_on->val, 0, (ULONG_PTR)co);
		BUG_ON(val > PCS_CO_EVENT_SIGNALED);
		if (val) {
			/* Event is already signaled, return coroutine into run queue */
			pcs_co_wakeup_waiting(co);
		}
		evloop->wait_on = NULL;
	} else {
		switch (pcs_co_state(co)) {
		case CO_RUNNING:
			pcs_co_set_state(co, CO_READY);
			add_to_runqueue(evloop, co);
			break;

		case CO_MIGRATED:
			pcs_file_job_submit_hash(co->migrate_job->io, &co->migrate_job->job, co->migrate_job->hash);
			break;
		}
	}

	current->sched_seq = evloop->co_sched_seq;
	pcs_co_set_current(current);
}

static void pcs_co_switch(struct pcs_coroutine * current, struct pcs_coroutine * co)
{
	co_log(LOG_DEBUG5, "co_sw: sw %p -> %p (state=%#x)", current, co, pcs_atomic32_load(&co->state));

	struct pcs_evloop *evloop = pcs_current_evloop;
	BUG_ON(current->evloop != evloop);
	BUG_ON(co->evloop != evloop);

	evloop->co_ctx_switches++;
	current->co_ctx_switches++;

#ifdef PCS_ADDRESS_SANITIZER
	BUG_ON(!co->stack_bottom || !co->stack_size);
	void *fake_stack;
	__sanitizer_start_switch_fiber(&fake_stack, co->stack_bottom, co->stack_size);
#endif
	pcs_ucontext_switch(&current->context, &co->context);
#ifdef PCS_ADDRESS_SANITIZER
	if (pcs_co_state(current) == CO_MIGRATED)
		__sanitizer_finish_switch_fiber(fake_stack, &current->migrate_job->stack_bottom, &current->migrate_job->stack_size);
	else
		__sanitizer_finish_switch_fiber(fake_stack, NULL, NULL);
#endif
	co_log(LOG_DEBUG5, "co_sw: ret to %p", current);

	pcs_co_switch_finish(current);
}

static void pcs_co_list_move(struct pcs_co_list *to, struct pcs_co_list *from, u32 nr)
{
	if (nr > from->nr)
		nr = from->nr;

	from->nr -= nr;
	to->nr += nr;

	while (nr--) {
		BUG_ON(cd_list_empty(&from->list));
		cd_list_move(from->list.next, &to->list);
	}
}

static void pcs_co_pool_apply_limit(struct pcs_evloop *evloop)
{
	/* Check local pool size */
	if (evloop->co_pool.nr < 2 * PCS_CO_POOL_SIZE)
		return;

	struct pcs_process *proc = evloop->proc;
	pthread_mutex_lock(&proc->co_list_mutex);

	/* Move coroutines from local to global pool */
	pcs_co_list_move(&evloop->co_pool, &proc->co_pool, evloop->co_pool.nr - PCS_CO_POOL_SIZE);

	/* Apply limit on global pool size */
	u32 nr_max = proc->co_list.nr * PCS_CO_POOL_PERCENT / 100;
	if (nr_max < proc->nr_evloops * PCS_CO_POOL_SIZE)
		nr_max = proc->nr_evloops * PCS_CO_POOL_SIZE;
	pcs_co_pool_free(proc, nr_max);

	pthread_mutex_unlock(&proc->co_list_mutex);
}

/* Internal for pcs_process event loop: coroutines are processed using this function */
void pcs_co_run(struct pcs_evloop * evloop)
{
	struct pcs_coroutine *co = get_runnable_co(evloop);
	if (co)
		pcs_co_switch(evloop->co_current, co);

	evloop->co_runqueue_cur ^= 1;
	evloop->co_sched_seq += 1 << 8;

	pcs_co_pool_apply_limit(evloop);
}

void pcs_co_bt_one(struct pcs_coroutine *co)
{
	s32 state = pcs_atomic32_fetch_and_or(&co->state, CO_BACKTRACE);
	switch (state & ~CO_BACKTRACE) {
	case CO_READY:
	case CO_WAITING:
		pcs_log(LOG_ERR, "Dump backtrace for co=%p(%s) state=%#x ctx_sw=%llu",
			co, co->name ? co->name : "", state, (llu)co->co_ctx_switches);
		show_trace_coroutine(&co->context);
		pcs_atomic32_and(&co->state, ~CO_BACKTRACE);
		break;

	case CO_RUNNING:
		if (co == pcs_current_co) {
			pcs_log(LOG_ERR, "Dump backtrace for current co=%p(%s) state=%#x ctx_sw=%llu",
				co, co->name ? co->name : "", state, (llu)co->co_ctx_switches);
			show_trace();
			pcs_atomic32_and(&co->state, ~CO_BACKTRACE);
			break;
		}
		/* FALLTHROUGH */

	case CO_MIGRATED:
		pcs_log(LOG_ERR, "Backtrace deferred for co=%p(%s) state=%#x ctx_sw=%llu",
			co, co->name ? co->name : "", state, (llu)co->co_ctx_switches);
		break;

	case CO_ZOMBIE:
	case CO_IDLE:
		/* No need to clear CO_BACKTRACE, it is ignored anyway */
		break;

	default:
		BUG();
	}
}

void pcs_co_bt(void)
{
	struct pcs_process *proc = pcs_current_proc;
	struct pcs_coroutine *co;

	pthread_mutex_lock(&proc->co_list_mutex);
	cd_list_for_each_entry(struct pcs_coroutine, co, &proc->co_list.list, list)
		pcs_co_bt_one(co);
	pthread_mutex_unlock(&proc->co_list_mutex);
}

void pcs_co_schedule(void)
{
	struct pcs_evloop *evloop = pcs_current_evloop;
	struct pcs_coroutine *co = get_runnable_co(evloop);
	if (!co)
		co = evloop->co_idle;

	pcs_co_switch(evloop->co_current, co);
}

static void PCS_UCONTEXT_FUNC _coroutine_start(void *arg)
{
	PCS_UCONTEXT_TOPMOST;

	struct pcs_coroutine * co = arg;

#ifdef PCS_ADDRESS_SANITIZER
	const void *stack_bottom;
	size_t stack_size;
	__sanitizer_finish_switch_fiber(NULL, &stack_bottom, &stack_size);

	/* When we arrive here for the first time, we has switched from the original
	 * stack of eventloop thread. It is the stack we will use later for co_idle */
	struct pcs_coroutine *co_idle = pcs_current_evloop->co_idle;
	if (!co_idle->stack_size) {
		co_idle->stack_bottom = stack_bottom;
		co_idle->stack_size = stack_size;
	}
#endif

	pcs_co_switch_finish(co);

	for (;;) {
		co->func(co, co->func_arg);

		pcs_co_done(co);

		/* coroutine can be reused from pool, so we need to restart a loop with new function to execute... */
	}
}

static struct pcs_coroutine * pcs_co_pool_alloc(struct pcs_evloop * evloop)
{
	if (!evloop->co_pool.nr) {
		/* Local pool is empty, look in global pool */
		struct pcs_process *proc = evloop->proc;
		pthread_mutex_lock(&proc->co_list_mutex);
		pcs_co_list_move(&evloop->co_pool, &proc->co_pool, PCS_CO_POOL_SIZE + 1);
		pthread_mutex_unlock(&proc->co_list_mutex);

		/* Global pool is empty too */
		if (!evloop->co_pool.nr)
			return NULL;
	}

	/* Take coroutine from local pool */
	struct pcs_coroutine * co = cd_list_first_entry(&evloop->co_pool.list, struct pcs_coroutine, run_list);
	cd_list_del_init(&co->run_list);
	evloop->co_pool.nr--;
	return co;
}

static struct pcs_coroutine * __pcs_co_alloc(struct pcs_process * proc, int add_size)
{
	struct pcs_coroutine *co = pcs_xmalloc(sizeof(*co) + add_size);
	memset(co, 0, sizeof(*co));

	cd_list_init(&co->run_list);
	cd_list_init(&co->wait_list);

	co->proc = proc;
	pcs_co_waitqueue_init(&co->join_wq);

	pthread_mutex_lock(&proc->co_list_mutex);
	cd_list_add_tail(&co->list, &proc->co_list.list);
	proc->co_list.nr++;
	pthread_mutex_unlock(&proc->co_list_mutex);
	return co;
}

static void pcs_co_alloc_ctx(struct pcs_coroutine * co)
{
#ifndef __WINDOWS__
	unsigned int page_size = sysconf(_SC_PAGESIZE);

	co->stack = mmap(0, PCS_CO_STACK_SIZE + 2 * page_size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
	if (co->stack == MAP_FAILED) {
		pcs_log_syserror(LOG_ERR, errno, "pcs_co_alloc_ctx: mmap co->stack failed");
		BUG();
	}

	/* Stack guard page */
	mprotect(co->stack, page_size, PROT_NONE);
	mprotect(co->stack + PCS_CO_STACK_SIZE + page_size, page_size, PROT_NONE);

	pcs_ucontext_init(&co->context, (u8 *)co->stack + page_size, PCS_CO_STACK_SIZE, _coroutine_start, co);
#else /* __WINDOWS__ */
	co->context.fiber = CreateFiberEx(0, PCS_CO_STACK_SIZE, 0, _coroutine_start, co);
	if (co->context.fiber == NULL) {
		pcs_log_syserror(LOG_ERR, GetLastError(), "pcs_co_alloc_ctx: CreateFiberEx failed");
		BUG();
	}
#endif /* __WINDOWS__ */

#ifdef PCS_ADDRESS_SANITIZER
	co->stack_bottom = co->stack + PCS_CO_STACK_SIZE + page_size;
	co->stack_size = PCS_CO_STACK_SIZE;
#endif
#ifdef USE_VALGRIND
	co->valgrind_stack_id = VALGRIND_STACK_REGISTER(co->stack + page_size, co->stack + page_size + PCS_CO_STACK_SIZE);
#endif

	/* account allocated stack to co allocation */
	pcs_alloc_account(co, PCS_CO_STACK_SIZE);
}

static struct pcs_coroutine * pcs_co_alloc(struct pcs_evloop * evloop)
{
	struct pcs_coroutine * co;

	co = pcs_co_pool_alloc(evloop);
	if (!co) {
		co = __pcs_co_alloc(evloop->proc, 0);
		pcs_co_alloc_ctx(co);
	}

	return co;
}

struct pcs_coroutine * pcs_co_create(struct pcs_context *ctx, int (*func)(struct pcs_coroutine *, void *), void * arg)
{
	struct pcs_evloop *evloop = pcs_current_evloop;
	BUG_ON(!evloop);

	struct pcs_coroutine *co = pcs_co_alloc(evloop);
	co->func = func;
	co->func_arg = arg;
	co->ctx = pcs_context_get(ctx);
	pcs_atomic32_store(&co->state, CO_READY);
	add_to_runqueue(evloop, co);
	return co;
}

void pcs_co_join(struct pcs_coroutine * co)
{
	if (!co)
		return;

	BUG_ON(!pcs_in_coroutine());
	BUG_ON(pcs_co_state(co) == CO_ZOMBIE);	/* this means code waits for co too late and potentially it could have been released already, i.e. double free */

	pcs_co_waitqueue_add(&co->join_wq);
	pcs_co_wait();
}

int pcs_co_wait(void)
{
	struct pcs_coroutine * current = pcs_current_co;
	pcs_atomic32_store(&current->state, CO_WAITING);
	current->result = 0;
	pcs_co_schedule();

	return current->result;
}

static void _co_poll_timer(void * data)
{
	struct pcs_coroutine * co = data;

	co->result = -PCS_CO_TIMEDOUT;
	pcs_co_wakeup(co);
}

int pcs_co_wait_timeout(int * timeout_p)
{
	if (!timeout_p || *timeout_p < 0)
		return pcs_co_wait();

	struct pcs_coroutine * co = pcs_current_co;
	struct pcs_timer timer;
	int res;

	abs_time_t wait_start = co->evloop->last_abs_time_ms;
	init_timer(co->proc, &timer, _co_poll_timer, co);
	mod_timer(&timer, *timeout_p);

	res = pcs_co_wait();

	del_timer_sync(&timer);

	if (res == -PCS_CO_TIMEDOUT) {
		*timeout_p = 0;
	} else {
		time_diff_t delay = get_elapsed_time(co->evloop->last_abs_time_ms, wait_start);
		if (delay >= *timeout_p)
			*timeout_p = 0;
		else
			*timeout_p -= (int)delay;
	}

	return res;
}

static void pcs_co_filejob_init(struct pcs_process * proc)
{
	const int nr_processors = pcs_nr_processors();

	if (!proc->co_io) {
		pcs_file_job_conn_start(proc, "co_io", &proc->co_io);
		pcs_file_job_set_queues_threads(proc->co_io, 1, 16);
	}

	if (!proc->co_cpu) {
		int nr = 4;
		if (nr > nr_processors)
			nr = nr_processors;

		pcs_file_job_conn_start(proc, "co_cpu", &proc->co_cpu);
		pcs_file_job_set_queues_threads(proc->co_cpu, 1, nr);
	}

	if (!proc->co_ssl) {
		int nr = pcs_is_aesni_supported() ? 2 : 4;
		if (nr > nr_processors)
			nr = nr_processors;

		pcs_file_job_conn_start(proc, "co_ssl", &proc->co_ssl);

		/* SSL encryption/decryption is single-threaded. Even though we offload it into another thread, we expect
		   that offload jobs started by a particular ssl socket, will be executed without reordering. */
		pcs_file_job_set_queues_threads(proc->co_ssl, nr, nr);
	}
}

static void pcs_co_filejob_fini(struct pcs_process * proc)
{
	if (proc->co_io) {
		pcs_file_job_conn_stop(proc->co_io);
		proc->co_io = NULL;
	}
	if (proc->co_cpu) {
		pcs_file_job_conn_stop(proc->co_cpu);
		proc->co_cpu = NULL;
	}
	if (proc->co_ssl) {
		pcs_file_job_conn_stop(proc->co_ssl);
		proc->co_ssl = NULL;
	}
}

static void pcs_co_term_job(void * arg)
{
	struct pcs_process * proc = arg;
	pcs_co_filejob_fini(proc);
}

struct _co_file_job
{
	struct pcs_file_job	fj;
	struct pcs_co_event	ev;
};

static void _co_filejob_done(void * arg)
{
	struct _co_file_job * co_fj = arg;
	pcs_co_event_signal(&co_fj->ev);
}

int pcs_co_filejob(struct pcs_file_job_conn * io, int (*func)(void *), void * data)
{
	return pcs_co_filejob_hash(io, func, data, (io->seq++) / 8);
}

int pcs_co_filejob_hash(struct pcs_file_job_conn * io, int (*func)(void *), void * data, unsigned int hash)
{
	struct _co_file_job co_fj;

	pcs_file_job_init(&co_fj.fj, func, data);
	pcs_job_init(io->proc, &co_fj.fj.done, _co_filejob_done, &co_fj);
	pcs_co_event_init(&co_fj.ev);

	pcs_file_job_submit_hash(io, &co_fj.fj, hash);

	pcs_co_event_wait(&co_fj.ev);

	return co_fj.fj.retval;
}

void pcs_co_set_name(struct pcs_coroutine * co, const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vsnprintf(co->name_buf, sizeof(co->name_buf), fmt, va);
	va_end(va);
	co->name = co->name_buf;
}

static int migrate_job_run(void *arg)
{
	struct pcs_coroutine *co = arg;

	BUG_ON(pcs_current_evloop != NULL);
	pcs_current_co = co;
#ifdef __WINDOWS__
	co->migrate_job->context.fiber = GetCurrentFiber();
#endif
#ifdef PCS_ADDRESS_SANITIZER
	void *fake_stack;
	__sanitizer_start_switch_fiber(&fake_stack, co->stack_bottom, co->stack_size);
#endif
	pcs_ucontext_switch(&co->migrate_job->context, &co->context);
#ifdef PCS_ADDRESS_SANITIZER
	__sanitizer_finish_switch_fiber(fake_stack, NULL, NULL);
#endif
	pcs_current_co = NULL;

	return 0;
}

static void migrate_job_return(void *arg)
{
	struct pcs_coroutine *co = arg;

	pcs_co_set_state(co, CO_READY);
	add_to_runqueue(pcs_current_evloop, co);
}

struct pcs_coroutine *pcs_co_migrate_to_thread_hash(struct pcs_file_job_conn *io, unsigned int hash)
{
	struct pcs_coroutine *co = pcs_current_co;

	s32 old_state = pcs_atomic32_exchange(&co->state, CO_MIGRATED);
	BUG_ON((old_state & ~CO_BACKTRACE) != CO_RUNNING);
	if (unlikely(old_state & CO_BACKTRACE)) {
		pcs_log(LOG_ERR, "Dump deferred backtrace for current co=%p(%s) state=%#x ctx_sw=%llu",
			co, co->name ? co->name : "", old_state, (llu)co->co_ctx_switches);
		show_trace();
	}

	if (!co->migrate_job)
		co->migrate_job = pcs_xmalloc(sizeof(*co->migrate_job));
	struct co_migrate_job *job = co->migrate_job;

	job->io = io;
	job->hash = hash;

	pcs_file_job_init(&job->job, migrate_job_run, co);
	pcs_job_init(io->proc, &job->job.done, migrate_job_return, co);

	/* pcs_co_switch_finish() will check CO_MIGRATED state and do remaining work */
	pcs_co_schedule();
	return co;
}

void pcs_co_migrate_from_thread(struct pcs_coroutine * co)
{
	BUG_ON(pcs_co_state(co) != CO_MIGRATED);

#ifdef PCS_ADDRESS_SANITIZER
	void *fake_stack;
	__sanitizer_start_switch_fiber(&fake_stack, co->migrate_job->stack_bottom, co->migrate_job->stack_size);
#endif
	pcs_ucontext_switch(&co->context, &co->migrate_job->context);
#ifdef PCS_ADDRESS_SANITIZER
	__sanitizer_finish_switch_fiber(fake_stack, NULL, NULL);
#endif
	pcs_co_switch_finish(co);
}

struct pcs_coroutine *pcs_co_migrate_to_thread(struct pcs_file_job_conn *io)
{
	return pcs_co_migrate_to_thread_hash(io, io->seq++);
}

static void _co_eventloop_action(void *arg)
{
	struct pcs_coroutine *co = arg;

	pcs_atomic32_store(&co->state, CO_READY);
	add_to_runqueue(pcs_current_evloop, co);
}

/* Ministack size. It is used only for thread suspension */
/* No less than 4K is required for ASAN and 64-bit Skylake to save AVX512 state, so let's use bigger value to be sure */
#define PCS_CO_WAITING_THREAD_SS (32*1024)
#define MSTACK_GUARD 	0xDEADBEAFBAAD1234ULL

struct thread_coroutine
{
	struct pcs_coroutine		co;
	int				done;
	int				new_fiber;
	pthread_cond_t			wait;
	pthread_mutex_t			wait_mutex;
	struct pcs_ucontext		wait_context;
	u64				mstack_guard;	/* to detect stack overflow */
#ifndef __WINDOWS__
	__pre_aligned(16) u8		mstack[PCS_CO_WAITING_THREAD_SS] __aligned(16);
#endif
};

static void PCS_UCONTEXT_FUNC _co_thread_suspend(void *arg)
{
	PCS_UCONTEXT_TOPMOST;

	struct thread_coroutine * tco = arg;
	struct pcs_process * proc = tco->co.proc;
	struct pcs_job job;

	/* Thread context with ministack */

#ifdef PCS_ADDRESS_SANITIZER
	__sanitizer_finish_switch_fiber(NULL, &tco->co.stack_bottom, &tco->co.stack_size);
#endif

	tco->done = 0;
	pthread_mutex_init(&tco->wait_mutex, NULL);
	pthread_cond_init(&tco->wait, NULL);
	BUG_ON(tco->mstack_guard != MSTACK_GUARD);

	/* Issue request to eventloop to spawn coroutine */
	pcs_job_init(proc, &job, _co_eventloop_action, tco);
	pcs_job_wakeup(&job);
	BUG_ON(tco->mstack_guard != MSTACK_GUARD);

	/* Wait for completion of coroutine context */
	pthread_mutex_lock(&tco->wait_mutex);
	while (!tco->done)
		pthread_cond_wait(&tco->wait, &tco->wait_mutex);
	pthread_mutex_unlock(&tco->wait_mutex);
	BUG_ON(tco->mstack_guard != MSTACK_GUARD);

	/* Jump back to thread with normal stack */
#ifdef PCS_ADDRESS_SANITIZER
	__sanitizer_start_switch_fiber(NULL, tco->co.stack_bottom, tco->co.stack_size);
#endif
	pcs_ucontext_switch(&tco->wait_context, &tco->co.context);
	BUG();
}

struct pcs_coroutine * pcs_move_to_coroutine(struct pcs_process * proc)
{
	struct pcs_coroutine * co;
	struct thread_coroutine * tco;

	BUG_ON(pcs_current_evloop != NULL);
	co = __pcs_co_alloc(proc, sizeof(*tco) - sizeof(struct pcs_coroutine));

	tco = (struct thread_coroutine*)co;
	tco->mstack_guard = MSTACK_GUARD;

#ifndef __WINDOWS__
	pcs_ucontext_init(&tco->wait_context, tco->mstack, PCS_CO_WAITING_THREAD_SS, _co_thread_suspend, tco);
#else
	co->context.fiber = ConvertThreadToFiberEx(NULL, 0);
	if (co->context.fiber != NULL) {
		tco->new_fiber = 1;
	} else {
		if (GetLastError() != ERROR_ALREADY_FIBER) {
			pcs_log_syserror(LOG_ERR, GetLastError(), "pcs_move_to_coroutine: ConvertThreadToFiberEx failed");
			BUG();
		}
		co->context.fiber = GetCurrentFiber();
		tco->new_fiber = 0;
	}
	tco->wait_context.fiber = CreateFiberEx(0, PCS_CO_WAITING_THREAD_SS, 0, _co_thread_suspend, tco);
	if (co->context.fiber == NULL) {
		pcs_log_syserror(LOG_ERR, GetLastError(), "pcs_move_to_coroutine: CreateFiberEx failed");
		BUG();
	}
#endif

	/* Now we are still in thread context with normal thread stack */

#ifdef PCS_ADDRESS_SANITIZER
	void *fake_stack;
	__sanitizer_start_switch_fiber(&fake_stack, tco->mstack + PCS_CO_WAITING_THREAD_SS, PCS_CO_WAITING_THREAD_SS);
#endif
#ifdef USE_VALGRIND
	tco->co.valgrind_stack_id = VALGRIND_STACK_REGISTER(tco->mstack, tco->mstack + PCS_CO_WAITING_THREAD_SS);
#endif
	pcs_ucontext_switch(&co->context, &tco->wait_context);
#ifdef PCS_ADDRESS_SANITIZER
	const void *stack_bottom;
	size_t stack_size;
	__sanitizer_finish_switch_fiber(fake_stack, &stack_bottom, &stack_size);

	/* When we arrive here for the first time, we has switched from the original
	 * stack of eventloop thread. It is the stack we will use later for co_idle */
	struct pcs_coroutine *co_idle = pcs_current_evloop->co_idle;
	if (!co_idle->stack_size) {
		co_idle->stack_bottom = stack_bottom;
		co_idle->stack_size = stack_size;
	}
#endif

	/* Now we are in coroutine context with thread stack */
	pcs_co_switch_finish(co);
	return co;
}

static void finish_move(void * arg)
{
	struct thread_coroutine * tco = arg;

	pthread_mutex_lock(&tco->wait_mutex);
	tco->done = 1;
	pthread_cond_signal(&tco->wait);
	pthread_mutex_unlock(&tco->wait_mutex);
}

void pcs_move_from_coroutine(void)
{
	BUG_ON(!pcs_in_coroutine());

	struct thread_coroutine * tco = (struct thread_coroutine *)pcs_current_co;
	struct pcs_job ret_job;
	struct pcs_evloop *evloop = pcs_current_evloop;
	struct pcs_process *proc = evloop->proc;
	BUG_ON(tco->mstack_guard != MSTACK_GUARD);

	pcs_cancelable_prepare_wait(&tco->co.io_wait, NULL);
	pcs_context_put(tco->co.ctx);
	tco->co.ctx = NULL;
	BUG_ON(!pcs_co_waitqueue_empty(&tco->co.join_wq));

	/* Coroutine context with thread stack
	 * Issue job to destroy coroutine and schedule it out.
	 * The trick is that job will be run after coroutine is scheduled out
	 */
	pcs_atomic32_store(&tco->co.state, CO_ZOMBIE);
	pcs_job_init(proc, &ret_job, finish_move, tco);
	// This job should only be executed after this co is scheduled away,
	// so add to local ones
	pcs_job_wakeup(&ret_job);
	pcs_co_schedule();

	/* Back to thread context with thread stack */
#ifdef USE_VALGRIND
	VALGRIND_STACK_DEREGISTER(tco->co.valgrind_stack_id);
#endif
	pthread_mutex_lock(&proc->co_list_mutex);
	BUG_ON(!proc->co_list.nr);
	proc->co_list.nr--;
	cd_list_del(&tco->co.list);
	pthread_mutex_unlock(&proc->co_list_mutex);

	pthread_mutex_destroy(&tco->wait_mutex);
	pthread_cond_destroy(&tco->wait);
	BUG_ON(tco->mstack_guard != MSTACK_GUARD);
#ifdef __WINDOWS__
	DeleteFiber(tco->wait_context.fiber);
	if (tco->new_fiber)
		ConvertFiberToThread();
#endif
	pcs_free(tco->co.migrate_job);
	pcs_free(tco);
}

void pcs_co_init_proc(struct pcs_process * proc)
{
	pthread_mutex_init(&proc->co_list_mutex, NULL);
	cd_list_init(&proc->co_list.list);
	cd_list_init(&proc->co_pool.list);

	pcs_job_init(proc, &proc->co_term_job, pcs_co_term_job, proc);
	pcs_add_termination_job(&proc->co_term_job);
	pcs_co_filejob_init(proc);
}

void pcs_co_init_evloop(struct pcs_evloop * evloop)
{
	cd_list_init(&evloop->co_runqueue[0].list);
	cd_list_init(&evloop->co_runqueue[1].list);
	cd_list_init(&evloop->co_pool.list);

	struct pcs_coroutine *co_idle = __pcs_co_alloc(evloop->proc, 0);
#ifdef __WINDOWS__
	co_idle->context.fiber = ConvertThreadToFiberEx(NULL, 0);
	if (co_idle->context.fiber == NULL) {
		pcs_log_syserror(LOG_ERR, GetLastError(), "pcs_co_init_evloop: ConvertThreadToFiberEx failed");
		BUG();
	}
#endif
	evloop->co_idle = co_idle;
	pcs_atomic32_store(&co_idle->state, CO_IDLE);
	co_idle->evloop = evloop;
	pcs_co_set_current(co_idle);
}

void pcs_co_fini_proc(struct pcs_process * proc)
{
	pcs_co_pool_free(proc, 0);
	pcs_co_file_pool_free(proc);
	BUG_ON(!cd_list_empty(&proc->co_list.list));
	BUG_ON(!cd_list_empty(&proc->co_pool.list));
	BUG_ON(proc->co_list.nr);
	BUG_ON(proc->co_pool.nr);
}

void pcs_co_fini_evloop(struct pcs_evloop * evloop)
{
	struct pcs_process *proc = evloop->proc;
	pthread_mutex_lock(&proc->co_list_mutex);
	/* Move everything from local to global pool, it will be freed later in pcs_co_fini_proc() */
	pcs_co_list_move(&proc->co_pool, &evloop->co_pool, evloop->co_pool.nr);
	cd_list_del(&evloop->co_idle->list);
	proc->co_list.nr--;
	pthread_mutex_unlock(&proc->co_list_mutex);

	BUG_ON(!cd_list_empty(&evloop->co_runqueue[0].list));
	BUG_ON(!cd_list_empty(&evloop->co_runqueue[1].list));
	BUG_ON(evloop->co_runqueue[0].nr);
	BUG_ON(evloop->co_runqueue[1].nr);
	BUG_ON(!cd_list_empty(&evloop->co_pool.list));
	BUG_ON(evloop->co_pool.nr);
	pcs_free(evloop->co_idle);
#ifdef __WINDOWS__
	ConvertFiberToThread();
#endif
}
