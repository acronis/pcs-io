/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

/*
 * file_job serves to offload jobs on file-system, which could require
 * significant time (f.e. creating and deleting chunks). All the jobs of this kind
 * are moved to a separate thread and strictly serialized, so that we do not try
 * to operate on more than one chunk at any time.
 *
 * Current limitation (due to handling ENOSPC) is that operations did complete recovery after
 * failure or at least did not fail, when seeing garbage from previous failed attempt.
 */
#include "log.h"
#include "pcs_malloc.h"
#include "pcs_file_job.h"

#define FJOB_TERMINATE_TIMEOUT (60*1000)

static pcs_thread_ret_t file_job_run(void * arg)
{
	struct pcs_file_job_queue * w = arg;

	pcs_thread_setname(w->conn->name);

#ifdef __WINDOWS__
	if (ConvertThreadToFiber(NULL) == NULL) {
		pcs_log_syserror(LOG_ERR, GetLastError(), "file_job_run: ConvertThreadToFiber failed");
		BUG();
	}
#endif
	pthread_mutex_lock(&w->lock);
	for (;;) {
		if (!cd_list_empty(&w->queue)) {
			struct pcs_file_job * j;

			j = cd_list_first_entry(&w->queue, struct pcs_file_job, list);
			cd_list_del_init(&j->list);

			pthread_mutex_unlock(&w->lock);

			j->retval = j->function(j->data);
			if (j->done.work)
				pcs_job_wakeup(&j->done);
			else
				pcs_file_job_free(j);
			pthread_mutex_lock(&w->lock);
			w->nr_tasks--;
			BUG_ON(w->nr_tasks < 0);
		} else if (w->shutdown) {
			break;
		} else {
			w->free_threads++;
			pthread_cond_wait(&w->wake, &w->lock);
			w->free_threads--;
		}
	}
	pthread_mutex_unlock(&w->lock);
#ifdef __WINDOWS__
	ConvertFiberToThread();
#endif
	return 0;
}

static void submit_job(struct pcs_file_job_queue *w, struct pcs_file_job * j)
{
	/* Put job into the queue */
	pthread_mutex_lock(&w->lock);
	cd_list_add_tail(&j->list, &w->queue);
	++w->nr_tasks;
	int wakeup = w->free_threads;
#ifdef __WINDOWS__
	if (wakeup)
		pthread_cond_signal(&w->wake);
	pthread_mutex_unlock(&w->lock);
#else
	pthread_mutex_unlock(&w->lock);
	if (wakeup)
		pthread_cond_signal(&w->wake);
#endif
}

int pcs_file_job_conn_start(struct pcs_process * proc, const char *name, struct pcs_file_job_conn ** new_io)
{
	int i;
	struct pcs_file_job_conn * io;

	io = pcs_xzmalloc(sizeof(*io));
	io->proc = proc;
	strncpy(io->name, name, sizeof(io->name));
	io->name[sizeof(io->name) - 1] = 0;
	io->nr_queues = 1;
	io->nr_threads = 1;

	for (i = 0; i < PCS_FILE_JOB_MAX_THREADS; i++) {
		struct pcs_file_job_queue * w = io->queues + i;
		cd_list_init(&w->queue);
		w->conn = io;
		pthread_mutex_init(&w->lock, NULL);
		pthread_cond_init(&w->wake, NULL);
	}

	*new_io = io;
	return 0;
}

static void pcs_file_job_stop_threads(struct pcs_file_job_conn *io)
{
	int i;

	for (i = 0; i < io->nr_queues; i++) {
		struct pcs_file_job_queue *w = io->queues + i;

		pthread_mutex_lock(&w->lock);
		w->shutdown = 1;
		pthread_cond_broadcast(&w->wake);
		pthread_mutex_unlock(&w->lock);
	}

	for (i = 0; i < io->cur_threads; i++) {
		int err = pcs_thread_timedjoin(io->threads[i], NULL, FJOB_TERMINATE_TIMEOUT);
		if (err)
			pcs_fatal("failed to join %s thread, err %d(%s)", io->name, err, strerror(err));
	}

	io->cur_threads = 0;

	for (i = 0; i < io->nr_queues; i++) {
		struct pcs_file_job_queue *w = io->queues + i;

		BUG_ON(!cd_list_empty(&w->queue));
		BUG_ON(w->free_threads);

		w->shutdown = 0;
	}
}

void pcs_file_job_conn_stop(struct pcs_file_job_conn * io)
{
	int i;

	pcs_file_job_stop_threads(io);

	for (i = 0; i < PCS_FILE_JOB_MAX_THREADS; i++) {
		struct pcs_file_job_queue * w = io->queues + i;

		pthread_mutex_destroy(&w->lock);
		pthread_cond_destroy(&w->wake);
	}
	pcs_free(io);
}

/* Enqueue file job. When it is complete, j->done() will be called */
void pcs_file_job_submit_hash(struct pcs_file_job_conn * io, struct pcs_file_job * j, unsigned int hash)
{
	BUG_ON(!pcs_in_evloop());

	j->retval = -1;
	pcs_job_init(io->proc, &j->done, j->done.work, j->done.data);

	while (io->cur_threads < io->nr_threads) {
		struct pcs_file_job_queue *w = io->queues + (io->cur_threads % io->nr_queues);

		sigset_t mask;
		pcs_profiler_block(pcs_current_evloop, &mask);
		if (pcs_thread_create(io->threads + io->cur_threads, NULL, file_job_run, w))
			pcs_fatal("Failed to create %s thread", io->name);
		pcs_profiler_unblock(pcs_current_evloop, &mask);
		io->cur_threads++;
	}

	unsigned int idx = hash % io->nr_queues;
	struct pcs_file_job_queue *w = io->queues + idx;
	submit_job(w, j);
}

void pcs_file_job_submit(struct pcs_file_job_conn * io, struct pcs_file_job * j)
{
	pcs_file_job_submit_hash(io, j, io->seq++);
}

void pcs_file_job_init(struct pcs_file_job * j, int (*fn)(void*), void * arg)
{
	cd_list_init(&j->list);
	j->retval = 0;
	j->function = fn;
	j->data = arg;
	j->done.work = NULL;
}

struct pcs_file_job * pcs_file_job_alloc(int (*fn)(void*), void * arg)
{
	struct pcs_file_job *job;

	job = pcs_xmalloc(sizeof(*job));
	pcs_file_job_init(job, fn, arg);

	return job;
}

void pcs_file_job_free(struct pcs_file_job *j)
{
	pcs_free(j);
}

void pcs_file_job_set_queues_threads(struct pcs_file_job_conn * io, int queues, int threads)
{
	if (threads > PCS_FILE_JOB_MAX_THREADS)
		threads = PCS_FILE_JOB_MAX_THREADS;
	if (threads < 1)
		threads = 1;

	if (queues < 1)
		queues = 1;
	if (queues > threads)
		queues = threads;

	if (threads < io->cur_threads || queues < io->nr_queues || (queues != io->nr_queues && io->nr_queues != io->nr_threads)) {
		/* Either too many threads may be started or thread to queue mapping has changed.
		 * Stop all running threads, they will be restarted automaticaly. */
		pcs_file_job_stop_threads(io);
	}

	io->nr_threads = threads;
	io->nr_queues = queues;
}

int pcs_file_job_set_threads(struct pcs_file_job_conn * io, int new_threads)
{
	pcs_file_job_set_queues_threads(io, new_threads, new_threads);
	return 0;
}
