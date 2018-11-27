/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_CO_H_
#define _PCS_CO_H_ 1

#include "pcs_config.h"
#include "pcs_process.h"
#include "pcs_thread.h"
#include "pcs_ucontext.h"
#include "std_list.h"

#ifdef PCS_ADDRESS_SANITIZER
#define PCS_CO_STACK_SIZE	(64*1024)
#else
#define PCS_CO_STACK_SIZE	(32*1024)
#endif
#define PCS_CO_POOL_SIZE	32
#define PCS_CO_POOL_PERCENT	10

#ifdef __WINDOWS__
#define PCS_CO_TIMEDOUT		ERROR_TIMEOUT
#define PCS_CO_CANCELED		ERROR_CANCELLED
#define PCS_CO_PIPE		WSAESHUTDOWN
#define PCS_CO_WOULDBLOCK	WSAEWOULDBLOCK
#else
#define PCS_CO_TIMEDOUT		ETIMEDOUT
#define PCS_CO_CANCELED		ECANCELED
#define PCS_CO_PIPE		EPIPE
#define PCS_CO_WOULDBLOCK	EWOULDBLOCK
#endif

struct pcs_context;

struct pcs_co_waitqueue
{
	struct cd_list		waiters;
};

struct pcs_co_event
{
	pcs_atomic_ptr_t	val;
};

struct pcs_cancelable {
	struct cd_list		list;	/* inserted into ctx->cancel_list */
	struct pcs_context	*ctx;
	struct pcs_co_event	ev;
};

struct pcs_coroutine
{
	struct cd_list		list;
	struct cd_list		run_list;	/* used for global runqueue and zombie pool */
	struct cd_list		wait_list;	/* used for waiting in waitqueue */
	struct pcs_process	*proc;
	struct pcs_evloop	*evloop;

	pcs_atomic32_t		state;
#define CO_ZOMBIE		0	/* coroutine can be reused or destroyed */
#define CO_IDLE			1	/* special coroutine for each eventloop */
#define CO_READY		2	/* coroutine is ready to run */
#define CO_RUNNING		3	/* coroutine is being executed right now */
#define CO_WAITING		4	/* coroutine is blocked on synchronization object */
#define CO_MIGRATED		5	/* coroutine is being executed outside of eventloop */
#define CO_BACKTRACE		0x10	/* flag: backtrace is in progress or deferred */

	struct pcs_cancelable	io_wait;

	unsigned int		sched_seq;
	u64			co_ctx_switches;

	int			(*func)(struct pcs_coroutine *, void * arg);
	void			*func_arg;
	void 			*stack;

	struct pcs_context	*ctx;

	struct pcs_ucontext	context;
	const void 		*stack_bottom;
	size_t			stack_size;
	unsigned int		valgrind_stack_id;

	int			result;
	struct pcs_co_waitqueue	join_wq;

	const char		*name;
	char			name_buf[128];

	struct co_migrate_job	*migrate_job;
};

#define PCS_INVALID_COROUTINE	((struct pcs_coroutine *)1UL)

/* Actual coroutine API */
PCS_API struct pcs_coroutine * pcs_co_create(struct pcs_context *ctx, int (*func)(struct pcs_coroutine *, void *), void * arg);
PCS_API void pcs_co_schedule(void);
PCS_API void pcs_co_join(struct pcs_coroutine * co);
PCS_API void pcs_co_bt(void);
void pcs_co_bt_one(struct pcs_coroutine *co);

static inline int pcs_co_state(struct pcs_coroutine *co)
{
	return pcs_atomic32_load(&co->state) & ~CO_BACKTRACE;
}

static inline int pcs_in_coroutine(void)
{
	struct pcs_evloop *evloop = pcs_current_evloop;
	return evloop && evloop->co_current != evloop->co_idle;
}

/**
   Suspend a caller coroutine and make it wait for a wakeup event. Wait at most @timeout ms.
   Upon exit, @timeout is updated with the remaining sleep time. If @timeout is NULL or negative,
   the sleep time is not bounded.
*/
PCS_API int pcs_co_wait_timeout(int *timeout);
/* Suspend a caller coroutine for an unbounded time waiting for a wakeup event. */
PCS_API int pcs_co_wait(void);
PCS_API void pcs_co_wakeup(struct pcs_coroutine * co);

struct pcs_file_job_conn;

PCS_API int pcs_co_filejob(struct pcs_file_job_conn * io, int (*func)(void *), void * data);
PCS_API int pcs_co_filejob_hash(struct pcs_file_job_conn * io, int (*func)(void *), void * data, unsigned int hash);

/* As snprintf is quite slow (more then 1 microsecond per call), it is better to be avoided on critical paths.
 * We provide macro to auto select either pcs_co_set_name or much faster variant pcs_co_set_name_fixed,
 * depending on number of arguments passed to pcs_co_set_name */
PCS_API void pcs_co_set_name(struct pcs_coroutine * co, const char *fmt, ...) __printf(2, 3);
static inline void pcs_co_set_name_fixed(struct pcs_coroutine * co, const char *name) { co->name = name; }

#define __pcs_co_set_name_verbatim(x) x
#define __pcs_co_set_name_select(_10, _9, _8, _7, _6, _5, _4, _3, _2, _1, _, ...) pcs_co_set_name ## _
#define pcs_co_set_name(co, ...) __pcs_co_set_name_verbatim(__pcs_co_set_name_select(__VA_ARGS__, , , , , , , , , , _fixed))(co, __VA_ARGS__)

PCS_API struct pcs_coroutine *pcs_co_migrate_to_thread_hash(struct pcs_file_job_conn *io, unsigned int hash);
PCS_API struct pcs_coroutine *pcs_co_migrate_to_thread(struct pcs_file_job_conn *io);
PCS_API void pcs_co_migrate_from_thread(struct pcs_coroutine * co);

PCS_API struct pcs_coroutine * pcs_move_to_coroutine(struct pcs_process * proc);
PCS_API void pcs_move_from_coroutine(void);

/* INTERNAL linkage to pcs_process.c, pcs_co_locks.c */
void pcs_co_init_proc(struct pcs_process * proc);
void pcs_co_init_evloop(struct pcs_evloop * evloop);
void pcs_co_fini_proc(struct pcs_process * proc);
void pcs_co_fini_evloop(struct pcs_evloop * evloop);
void pcs_co_run(struct pcs_evloop * evloop);
int pcs_co_find_runnable(struct pcs_evloop *evloop);
void pcs_co_wakeup_waiting(struct pcs_coroutine *co);

#endif /* _PCS_CO_H_ */
