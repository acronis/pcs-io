/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_PROCESS_H_
#define _PCS_PROCESS_H_ 1

#include "pcs_types.h"
#include "std_list.h"
#include "timer.h"
#include "pcs_fd_gc.h"
#include "pcs_poll.h"
#include "pcs_profiler.h"
#include "pcs_watchdog.h"
#include "pcs_thread.h"
#include "pcs_atomic.h"

#define PCS_PROCESS_STACK_SIZE	(8*1024*1024)

struct pcs_job
{
	struct cd_list	list;
	struct pcs_process *proc;
	void		*data;
	void		(*work)(void *);
};

struct pcs_coroutine;
struct pcs_co_event;
struct pcs_co_rwlock;

struct pcs_co_list
{
	struct cd_list	list;
	u32		nr;
};

struct pcs_process
{
	char		name[16];

	struct pcs_evloop   *evloops;

	int		exit_code;

	u32		nr_evloops;
	pcs_atomic32_t	loop_enter;

#if defined(HAVE_EPOLL)
	int		epollfd;
#elif defined(HAVE_KQUEUE)
	int		kqueue;
#elif defined(__SUN__)
	int		port;
#elif defined(__WINDOWS__)
	HANDLE		iocp;
#endif
	struct cd_list	sig_list;	/* signal handlers list */
	unsigned int	n_ioconns;
	struct cd_list	ioconns;
	struct cd_list	kill_list;
	struct pcs_job	kill_ioconn_job;

	int		msg_count;
	int		sio_count;
	int		conn_count;

	pthread_mutex_t		remote_job_mutex;
	struct cd_list		remote_job_queue;
	struct pcs_event_ioconn	*remote_job_event;
	pcs_atomic32_t		remote_job_present;

	/* coroutines */
	pthread_mutex_t		co_list_mutex;		/* protects co_list and co_pool */
	struct pcs_co_list	co_list;
	struct pcs_co_list	co_pool;
	pcs_atomic_ptr_t	co_file_pool;
	struct pcs_co_rwlock	*exec_lock;

	pthread_mutex_t		co_runqueue_mutex;	/* protects co_runqueue */
	struct cd_list		co_runqueue;		/* global runqueue */
	pcs_atomic32_t		co_runqueue_nr;		/* size of global runqueue */

	pcs_atomic32_t		co_ready_count;		/* total number of ready coroutines in all runqueues
							   and coroutines being executed now */
	pcs_atomic32_t		polling_evloops_count;	/* number of eventloops that do polling */

	pcs_atomic32_t		evloop_wakeup_event_sent; /* evloop_wakeup_event is signaled nut not processed yet */
	struct pcs_event_ioconn	*evloop_wakeup_event;	/* event to wakeup eventloop that do polling */

	struct pcs_file_job_conn * co_io;
	struct pcs_file_job_conn * co_cpu;
	struct pcs_file_job_conn * co_ssl;

	struct cd_list	term_jobs;

	/* FD GC */
	struct cd_list	fd_users;

	/* evloops synchronization */
	struct pcs_thread_barrier	barrier;
};

#define PCS_MAX_EVENTS_NR	128
#define PCS_EVLOOP_RUNQUEUE_SIZE	256	/* must be power of 2 */

struct pcs_evloop_runqueue {
	pcs_atomic32_t		head;
	pcs_atomic32_t		tail;
	struct pcs_coroutine	*buf[PCS_EVLOOP_RUNQUEUE_SIZE];
};

struct pcs_evloop {
	pcs_thread_t	thr;
	unsigned long	thr_id;

	struct pcs_process  *proc;

	int	id;
	int	closing;

#if defined(HAVE_EPOLL)
	struct epoll_event	events[PCS_MAX_EVENTS_NR];
#elif defined(HAVE_KQUEUE)
	struct kevent		events[PCS_MAX_EVENTS_NR];
#elif defined(__SUN__)
	port_event_t		events[PCS_MAX_EVENTS_NR];
#elif defined(__WINDOWS__)
	OVERLAPPED_ENTRY	events[PCS_MAX_EVENTS_NR];
#endif
	int			nr_events;

	struct cd_list	jobs;
	struct pcs_timer_tree timers;

	abs_time_t	last_abs_time_us;
	abs_time_t	last_abs_time_ms;
	abs_time_t	last_poll_time_us;

	u32		poll_count;

	/* coroutines */
	struct pcs_coroutine *co_idle;
	struct pcs_coroutine *co_current;
	struct pcs_coroutine *co_next;

	struct pcs_evloop_runqueue	co_runqueue;
	u32			steal_target;

	u64		co_ctx_switches;

	struct pcs_co_list	co_pool;

	struct pcs_co_event	*wait_on;

	/* debugging */
	struct pcs_profiler *prof;
	struct pcs_watchdog *wd;
};

#define pcs_current		(pcs_thread_tls())
#define pcs_current_evloop      (pcs_current->evloop)
#define pcs_current_proc	(pcs_current->proc)
#define pcs_current_co		(pcs_current->co)

PCS_API int pcs_process_alloc(struct pcs_process ** proc);
PCS_API int pcs_process_init(struct pcs_process * proc);
PCS_API void pcs_process_fini(struct pcs_process * proc);
PCS_API void pcs_process_free(struct pcs_process * proc);

void pcs_evloop_lock_init(pthread_mutex_t *m, const pthread_mutexattr_t *attr);
void pcs_evloop_lock(pthread_mutex_t *m);
void pcs_evloop_unlock(pthread_mutex_t *m);
void pcs_evloop_lock_destroy(pthread_mutex_t *m);

PCS_API int pcs_process_start(struct pcs_process * proc, const char *name);
PCS_API int pcs_process_wait(struct pcs_process * proc);
void pcs_might_block(void);
PCS_API void pcs_process_terminate(struct pcs_process * proc);		/* safe to call from any thread */

/*
 * NOTE: jobs can be safely submitted/wokenup:
 * 1. before pcs_process started
 * 2. in evloop (after pcs_process started).
 * 3. to remote pcs_process
 * i.e. it's safe to submit job to pcs_process from any context unlike other primiteves like timers, async I/O, etc.
 */
PCS_API void pcs_job_init(struct pcs_process * proc, struct pcs_job * job, void (*work)(void *), void * data);
PCS_API void pcs_job_del(struct pcs_job * job);
PCS_API void pcs_job_wakeup(struct pcs_job * job);			/* safe to call from any thread, see above NOTE */
PCS_API void pcs_add_termination_job(struct pcs_job * job);

/* Execute function in the context of the event loop. Creates pcs_job internally. */
PCS_API void pcs_call_in_job(struct pcs_process* proc, void (*fn)(void*), void* arg);
PCS_API void pcs_call_in_job2(struct pcs_process* proc, void (*fn)(void*, void*), void* arg1, void* arg2);

int pcs_process_oom_adjust(void);

int pcs_process_need_poll(struct pcs_evloop *evloop);
void pcs_process_ping_watchdog(struct pcs_evloop *evloop);

static inline int pcs_in_evloop(void)
{
	return likely(pcs_current_evloop != NULL);
}

static inline int pcs_process_is_running(struct pcs_process *proc)
{
	return (pcs_atomic32_load(&proc->loop_enter) != 0);
}

static inline int pcs_nr_evloops(void)
{
	return pcs_current_proc->nr_evloops;
}

static inline abs_time_t get_abs_time_fast_ms(void)
{
	struct __pcs_current * curr = pcs_current;
	return curr->evloop ? curr->evloop->last_abs_time_ms : get_abs_time_us() / 1000;
}

static inline abs_time_t get_abs_time_fast_us(void)
{
	struct __pcs_current * curr = pcs_current;
	return curr->evloop ? curr->evloop->last_abs_time_us : get_abs_time_us();
}

static inline u32 runqueue_size(struct pcs_evloop_runqueue *runqueue)
{
	u32 head = pcs_atomic32_load(&runqueue->head);
	u32 tail = pcs_atomic32_load(&runqueue->tail);
	return tail - head;
}

#endif /* _PCS_PROCESS_H_ */
