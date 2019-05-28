/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_types.h"

#ifndef __WINDOWS__
#include <sys/wait.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#endif

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#include "pcs_process.h"
#include "pcs_coroutine.h"
#include "pcs_config.h"
#include "pcs_malloc.h"
#include "pcs_poll.h"
#include "pcs_thread.h"
#include "pcs_iocp.h"
#include "pcs_event_ioconn.h"
#include "pcs_signal.h"
#include "log.h"
#include "timer.h"
#include "pcs_atomic.h"

#define MAX_POLL_INTERVAL	250		/* usec */
#define WATCHDOG_PING_INTERVAL	(500 * 1000)	/* usec */

/* Jobs. Actually, job is a special case of timer with zero timeout.
 * So that this code is redundant. It is just cheaper, no tree balancing etc.
 */

static inline int pending_jobs(struct pcs_evloop * evloop)
{
	return !cd_list_empty(&evloop->jobs) || pcs_atomic32_load(&evloop->proc->remote_job_present);
}

static void check_jobs(struct pcs_evloop * evloop)
{
	struct pcs_process *proc = evloop->proc;
	CD_LIST_HEAD(local_q);

	cd_list_splice_tail(&evloop->jobs, &local_q);

	if (pcs_atomic32_load(&proc->remote_job_present)) {
		pthread_mutex_lock(&proc->remote_job_mutex);
		cd_list_splice_tail(&proc->remote_job_queue, &local_q);
		pcs_atomic32_store(&proc->remote_job_present, 0);
		pthread_mutex_unlock(&proc->remote_job_mutex);
	}

	while (!cd_list_empty(&local_q)) {
		struct pcs_job * j = cd_list_first_entry(&local_q, struct pcs_job, list);
		BUG_ON(j->proc != proc);

		cd_list_del_init(&j->list);
		j->work(j->data);
	}
}

static void abort_jobs(struct pcs_process * proc)
{
	/* Cannot really do anything about them. */
	cd_list_init(&proc->evloops[0].jobs);
	cd_list_init(&proc->remote_job_queue);
}

static void run_term_jobs(struct pcs_process * proc)
{
	while (!cd_list_empty(&proc->term_jobs)) {
		struct pcs_job * j = cd_list_first_entry(&proc->term_jobs, struct pcs_job, list);
		cd_list_del_init(&j->list);
		j->work(j->data);
	}
}

void pcs_job_wakeup(struct pcs_job * job)
{
	/* local evloop job queueing */
	if (likely(pcs_current_proc == job->proc)) {
		if (cd_list_empty(&job->list))
			cd_list_add_tail(&job->list, &pcs_current_evloop->jobs);
		return;
	}

	/* remote job queueing */

	if (!cd_list_empty(&job->list)) {
		pcs_log(LOG_ERR, "BUG: remote job %p double wakeup, list prev %p next %p, work fn %p", job, job->list.prev, job->list.next, job->work);
		BUG();
	}

	struct pcs_process *proc = job->proc;
	pthread_mutex_lock(&proc->remote_job_mutex);
	int wakeup = cd_list_empty(&proc->remote_job_queue);
	cd_list_add_tail(&job->list, &proc->remote_job_queue);
	pcs_atomic32_store(&proc->remote_job_present, 1);
	pthread_mutex_unlock(&proc->remote_job_mutex);
	if (wakeup)
		pcs_event_ioconn_wakeup(proc->remote_job_event);
}

void pcs_add_termination_job(struct pcs_job * job)
{
	struct pcs_process *proc = job->proc;
	BUG_ON(pcs_current_proc != proc && pcs_process_is_running(proc));
	if (cd_list_empty(&job->list))
		cd_list_add(&job->list, &proc->term_jobs);
}

void pcs_job_del(struct pcs_job * job)
{
	cd_list_del_init(&job->list);
}

void pcs_job_init(struct pcs_process * proc, struct pcs_job * job, void (*work)(void *), void * data)
{
	job->proc = proc;
	job->work = work;
	job->data = data;
	cd_list_init(&job->list);
}

struct async_job {
	struct pcs_job job;
	union {
		void (*fn1)(void*);
		void (*fn2)(void*, void*);
	};
	void* arg1;
	void* arg2;
};

static void async_worker1(void* ctx)
{
	struct async_job* j = ctx;
	j->fn1(j->arg1);
	pcs_free(j);
}

static void async_worker2(void* ctx)
{
	struct async_job* j = ctx;
	j->fn2(j->arg1, j->arg2);
	pcs_free(j);
}

/* Execute function in the context of the event loop. Creates pcs_job internally. */
void pcs_call_in_job(struct pcs_process* proc, void (*fn)(void*), void* arg)
{
	struct async_job* j = pcs_xmalloc(sizeof(*j));
	j->fn1  = fn;
	j->arg1 = arg;
	pcs_job_init(proc, &j->job, async_worker1, j);
	pcs_job_wakeup(&j->job);
}

void pcs_call_in_job2(struct pcs_process* proc, void (*fn)(void*, void*), void* arg1, void* arg2)
{
	struct async_job* j = pcs_xmalloc(sizeof(*j));
	j->fn2  = fn;
	j->arg1 = arg1;
	j->arg2 = arg2;
	pcs_job_init(proc, &j->job, async_worker2, j);
	pcs_job_wakeup(&j->job);
}

static void set_abs_time_fast(struct pcs_evloop *evloop)
{
	evloop->last_abs_time_us = get_abs_time_us();
	evloop->last_abs_time_ms = evloop->last_abs_time_us / 1000;
}

static void eventloop_enter(struct pcs_evloop * evloop)
{
	pcs_current_proc = evloop->proc;
	pcs_current_evloop = evloop;
	pcs_current_co = NULL;

	pcs_thread_setname(evloop->proc->name);
	evloop->thr_id = pcs_thread_id();

	s32 e = pcs_atomic32_fetch_and_add(&evloop->proc->loop_enter, 1);
	BUG_ON(e > INT32_MAX / 2);
}

static void eventloop_leave(struct pcs_evloop * evloop)
{
	pcs_current_evloop = NULL;
	pcs_current_co = NULL;

	s32 e = pcs_atomic32_fetch_and_sub(&evloop->proc->loop_enter, 1);
	BUG_ON(e <= 0);
}

static void remote_job_data_ready(void *priv)
{
}

static int pcs_remote_init(struct pcs_process *proc)
{
	pthread_mutex_init(&proc->remote_job_mutex, NULL);
	cd_list_init(&proc->remote_job_queue);
	return pcs_event_ioconn_init(proc, &proc->remote_job_event, remote_job_data_ready, NULL);
}

static void pcs_remote_fini(struct pcs_process *proc)
{
	BUG_ON(!cd_list_empty(&proc->remote_job_queue));
	pcs_event_ioconn_close(proc->remote_job_event);
	pthread_mutex_destroy(&proc->remote_job_mutex);
}

static int has_tasks_to_do(struct pcs_evloop *evloop)
{
	if (pending_jobs(evloop))
		return 1;
	if (evloop->co_next)
		return 1;
	if (runqueue_size(&evloop->co_runqueue))
		return 1;
	if (pcs_atomic32_load(&evloop->proc->co_runqueue_nr))
		return 1;
	return evloop->closing;
}

static void poll_io_events(struct pcs_evloop *evloop, int timeout)
{
	struct pcs_process *proc = evloop->proc;
	pcs_atomic32_inc(&proc->polling_evloops_count);
	pcs_profiler_leave(evloop, 0);
	evloop->poll_count++;
	pcs_poll_wait(evloop, timeout);
	evloop->poll_count++;
	pcs_profiler_enter(evloop);
	pcs_atomic32_dec(&proc->polling_evloops_count);
}

static void warn_evloop_not_working(struct pcs_evloop *evloop)
{
	abs_time_t elapsed = get_elapsed_time(evloop->last_abs_time_us, evloop->last_poll_time_us);
	if (elapsed > PCS_LOOP_WATCHDOG_TIME * 1000)
		pcs_log(LOG_WARN, "watchdog: pcs evloop #%d was not working for %llu sec", evloop->id, (llu)elapsed/1000000);
}

int pcs_process_need_poll(struct pcs_evloop *evloop)
{
	if (pending_jobs(evloop) || evloop->closing)
		return 1;

	set_abs_time_fast(evloop);
	if (evloop->last_abs_time_us < evloop->last_poll_time_us + MAX_POLL_INTERVAL)
		return 0;

	if (!pcs_atomic32_load(&evloop->proc->polling_evloops_count))
		return 1;

	if (!get_timers_timeout(&evloop->timers))
		return 1;

	return 0;
}

void pcs_process_ping_watchdog(struct pcs_evloop *evloop)
{
	if (evloop->last_abs_time_us < evloop->last_poll_time_us + WATCHDOG_PING_INTERVAL)
		return;

	evloop->poll_count += 2;
	pcs_profiler_leave(evloop, 0);
	pcs_profiler_enter(evloop);
	warn_evloop_not_working(evloop);
	evloop->last_poll_time_us = evloop->last_abs_time_us;
}

pcs_thread_ret_t pcs_process_eventloop(void * arg)
{
	struct pcs_evloop *evloop = (struct pcs_evloop *)arg;
	struct pcs_process *proc = evloop->proc;

	eventloop_enter(evloop);

	set_abs_time_fast(evloop);
	pcs_co_enter_evloop(evloop);
	pcs_profiler_start(evloop);
	pcs_watchdog_init_evloop(evloop);

	if (evloop->id == 0)
		pcs_co_filejob_init(proc);

	pcs_thread_barrier_wait(&proc->barrier);

	pcs_profiler_enter(evloop);
	if (evloop->id == 0)
		pcs_watchdog_start(proc);
	evloop->last_poll_time_us = evloop->last_abs_time_us;

	while (!evloop->closing) {
		check_jobs(evloop);
		pcs_co_run(evloop);

		int timeout = check_timers(evloop);

		if (has_tasks_to_do(evloop)) {
			timeout = 0;
		} else if (pcs_atomic32_load(&proc->co_ready_count) >= proc->nr_evloops - pcs_atomic32_load(&proc->polling_evloops_count)) {
			pcs_co_steal(evloop);
			timeout = 0;
		}

		poll_io_events(evloop, timeout);
		set_abs_time_fast(evloop);
		pcs_poll_process_events(evloop);
		warn_evloop_not_working(evloop);
		evloop->last_poll_time_us = evloop->last_abs_time_us;
	}

	check_jobs(evloop);
	pcs_profiler_leave(evloop, 0);

	pcs_thread_barrier_wait(&proc->barrier);

	if (evloop->id == 0) {
		/* Run delayed jobs to kill ioconns, coroutines etc. */
		run_term_jobs(proc);
		pcs_co_filejob_fini(proc);
		pcs_watchdog_stop(proc);
	}

	eventloop_leave(evloop);
	pcs_co_exit_evloop(evloop);
	pcs_profiler_stop(evloop);

	return 0;
}

void pcs_init_fd_user(struct pcs_process * proc, struct pcs_fd_user * fu,
		      void * data, int (*gc)(void *))
{
	fu->data = data;
	fu->gc = gc;

	cd_list_add_tail(&fu->list, &proc->fd_users);
}

int pcs_fd_gc(struct pcs_process * proc)
{
	struct pcs_fd_user * fu;
	int done = 0;

	cd_list_for_each_entry(struct pcs_fd_user, fu, &proc->fd_users, list) {
		done += fu->gc(fu->data);
	}
	return done;
}

int pcs_fd_gc_on_error(struct pcs_process * proc, int err, int times)
{
#ifndef __WINDOWS__
	if (err != EMFILE && err != ENFILE)
#else
	if (err != WSAEMFILE)
#endif
		return -err;

	int total = 0;
	do {
		int done = pcs_fd_gc(proc);
		if (!done)
			break;
		total += done;
	} while (--times > 0);
	return total;
}

struct terminate_job
{
	struct pcs_job		job;
	int			cnt;
};

static void send_terminate_job(struct terminate_job *job)
{
	struct pcs_process *proc = job->job.proc;

	pthread_mutex_lock(&proc->remote_job_mutex);
	int wakeup = cd_list_empty(&proc->remote_job_queue);
	cd_list_add_tail(&job->job.list, &proc->remote_job_queue);
	pcs_atomic32_store(&proc->remote_job_present, 1);

	/* Call pcs_event_ioconn_wakeup() under lock in order
	 * to avoid possible races with pcs_process destruction */
	if (wakeup)
		pcs_event_ioconn_wakeup(proc->remote_job_event);

	pthread_mutex_unlock(&proc->remote_job_mutex);
}

static void terminate_job(void *arg)
{
	struct terminate_job *job = arg;

	if (!pcs_current_evloop->closing) {
		pcs_current_evloop->closing = 1;
		job->cnt--;
	}

	if (job->cnt > 0)
		send_terminate_job(job);
	else
		pcs_free(job);
}

void pcs_process_terminate(struct pcs_process * proc)
{
	struct terminate_job *job = pcs_xzmalloc(sizeof(*job));
	pcs_job_init(proc, &job->job, terminate_job, job);
	job->cnt = proc->nr_evloops;

	if (!pcs_in_evloop()) {
		send_terminate_job(job);
	} else {
		BUG_ON(pcs_current_proc != proc);
		terminate_job(job);
	}
}

int pcs_process_alloc(struct pcs_process ** proc)
{
	*proc = pcs_xmalloc(sizeof(**proc));
	return pcs_process_init(*proc);
}

static void pcs_init_evloops(struct pcs_process *proc)
{
	int i;
	for (i = 0; i < proc->nr_evloops; ++i) {
		struct pcs_evloop *evloop = &proc->evloops[i];
		evloop->proc = proc;
		evloop->id = i;
		cd_list_init(&evloop->jobs);
		init_timers(&evloop->timers);
		pcs_co_init_evloop(evloop);
	}
}

static void pcs_init_nr_evloops(struct pcs_process *proc)
{
	const char *env_nr_evloops = getenv("PCS_NR_EVLOOPS");

	if (env_nr_evloops == NULL)
		proc->nr_evloops = 1;
	else if (atoi(env_nr_evloops) < 0)
		proc->nr_evloops = 1;
	else if (atoi(env_nr_evloops) == 0)
		proc->nr_evloops = pcs_nr_processors();
	else
		proc->nr_evloops = atoi(env_nr_evloops);
}

int pcs_process_init(struct pcs_process * proc)
{
	memset(proc, 0, sizeof(*proc));

	cd_list_init(&proc->sig_list);
	cd_list_init(&proc->ioconns);
	cd_list_init(&proc->kill_list);
	cd_list_init(&proc->term_jobs);
	cd_list_init(&proc->fd_users);
	pcs_job_init(proc, &proc->kill_ioconn_job, ioconn_kill_all, proc);

	pcs_init_nr_evloops(proc);
	pcs_thread_barrier_init(&proc->barrier, proc->nr_evloops + 1);
	proc->evloops = pcs_xzmalloc(sizeof(struct pcs_evloop) * proc->nr_evloops);

	pcs_init_evloops(proc);

	int rc;
	if ((rc = pcs_poll_init(proc))) {
		pcs_log(LOG_ERR, "pcs_process: failed to initialize epoll");
		return rc;
	}

	if ((rc = pcs_remote_init(proc))) {
		pcs_log(LOG_ERR, "pcs_process: failed to initialize remote");
		return rc;
	}

	if ((rc = pcs_co_init_proc(proc))) {
		pcs_log(LOG_ERR, "pcs_process: failed to initialize coroutines");
		return rc;
	}

	return 0;
}

static void pcs_fini_evloops(struct pcs_process *proc)
{
	int i;
	for (i = 0; i < proc->nr_evloops; i++) {
		struct pcs_evloop *evloop = &proc->evloops[i];
		pcs_co_fini_evloop(evloop);
		BUG_ON(!cd_list_empty(&evloop->jobs));
		fini_timers(&evloop->timers);
	}
}

void pcs_process_fini(struct pcs_process * proc)
{
	pcs_fini_evloops(proc);

	pcs_remote_fini(proc);
	pcs_signal_fini(proc);
	pcs_co_fini_proc(proc);
	pcs_poll_fini(proc);

	pcs_free(proc->evloops);

	pcs_thread_barrier_fini(&proc->barrier);

	BUG_ON(!cd_list_empty(&proc->term_jobs));

	BUG_ON(!cd_list_empty(&proc->ioconns));
	BUG_ON(proc->msg_count);
	BUG_ON(proc->sio_count);
	BUG_ON(proc->conn_count);
}

static int join_threads(struct pcs_process *proc, int nr)
{
	int err = 0;

	int i;
	for (i = 0; i < nr; i++) {
		int tmp = pcs_thread_join(proc->evloops[i].thr);
		if (err == 0)
			err = tmp;
	}

	return err;
}

static void __pcs_process_start_abort(struct pcs_process *proc)
{
	abort_jobs(proc);
	abort_timers(&proc->evloops[0].timers);

	int i;
	for (i = 0; i < proc->nr_evloops; i++)
		proc->evloops[i].closing = 1;
}


int pcs_process_start(struct pcs_process * proc, const char *name)
{
	BUG_ON(pcs_process_is_running(proc));

	get_abs_time_us();	/* init time poisoning */

	strncpy(proc->name, name, sizeof(proc->name) - 1);
	proc->name[sizeof(proc->name) - 1] = 0;

	pcs_thread_attr_t attr;
	memset(&attr, 0, sizeof(attr));
	attr.stack_size = PCS_PROCESS_STACK_SIZE;

	int i;
	for (i = 0; i < proc->nr_evloops; i++) {
		if (pcs_thread_create(&proc->evloops[i].thr, &attr, pcs_process_eventloop, &proc->evloops[i])) {
			pcs_log(LOG_WARN, "failed to spawn %d'th evloop", i);
			__pcs_process_start_abort(proc);
			pcs_thread_barrier_reset(&proc->barrier, i);
			join_threads(proc, i);
			return -1;
		}
	}

	pcs_thread_barrier_wait(&proc->barrier);
	pcs_thread_barrier_reset(&proc->barrier, proc->nr_evloops);
	return 0;
}

int pcs_process_wait(struct pcs_process * proc)
{
	int err = join_threads(proc, proc->nr_evloops);
	return err ? err : proc->exit_code;
}

void pcs_process_free(struct pcs_process *proc)
{
	if (!proc)
		return;

	pcs_process_terminate(proc);
	pcs_process_wait(proc);
	pcs_process_fini(proc);
	pcs_free(proc);
}

void pcs_might_block(void)
{
	/* we should not issue blocking calls like open()/read()/write()/close()/fsync() from event loop thread */
#if 0
	/* Disable pcs_might_block  since current implementation of some libraries (libpcs_journal, libpcs_auth)
	 * is incompatible with it (((
	 * We will enable it later when refactoring will be done.
	 */
	BUG_ON(__is_eventloop);
#endif
}


#ifdef HAVE_OOM_ADJUST
#define PCS_OOM_ADJ_VALUE           "-17"
#define PCS_OOM_SCORE_ADJ_VALUE	    "-1000"

#include "pcs_sync_io.h"

int pcs_process_oom_adjust(void)
{
	/* set OOM adjust */
	const char *oom_adj = "/proc/self/oom_adj";
	const char *oom_score_adj = "/proc/self/oom_score_adj";
	int has_oom_score_adj = 1;

	/* In newer kernel versions "/proc/self/oom_adj" is deprecated,
	 * need to use "/proc/self/oom_score_adj" instead */
	int rc, fd = open(oom_score_adj, O_WRONLY | O_CLOEXEC);

	if (fd < 0) {
		fd = open(oom_adj, O_WRONLY | O_CLOEXEC);
		if (fd < 0) {
			pcs_log(LOG_ERR, "Unable open file %s - %s", oom_adj, strerror(errno));
			return -1;
		}
		has_oom_score_adj = 0;
	}

	rc = strlen(has_oom_score_adj ? PCS_OOM_SCORE_ADJ_VALUE : PCS_OOM_ADJ_VALUE);
	if (pcs_sync_swrite(fd, has_oom_score_adj ? PCS_OOM_SCORE_ADJ_VALUE : PCS_OOM_ADJ_VALUE, rc) != rc) {
		pcs_log(LOG_ERR, "Can't write to file %s - %s", has_oom_score_adj ? oom_score_adj : oom_adj, strerror(errno));
		close(fd);
		return -1;
	}

	rc = close(fd);
	if (rc < 0)
		pcs_log(LOG_ERR, "Can't close file %s - %s", has_oom_score_adj ? oom_score_adj : oom_adj, strerror(errno));

	return rc;
}
#else	/* HAVE_OOM_ADJUST */
int pcs_process_oom_adjust(void) {return 0;}
#endif	/* HAVE_OOM_ADJUST */
