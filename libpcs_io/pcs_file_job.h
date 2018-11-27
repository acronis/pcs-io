/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_FILE_JOB_H_
#define _PCS_FILE_JOB_H_ 1

#include "pcs_process.h"

#define PCS_FILE_JOB_MAX_THREADS	256

struct pcs_file_job_conn;

struct pcs_file_job
{
	struct cd_list	list;
	int		retval;

	int		(*function)(void * data);
	void		*data;

	struct pcs_job	done;
};

struct pcs_file_job_queue
{
	struct pcs_file_job_conn *conn;

	pthread_mutex_t		lock;
	pthread_cond_t		wake;
	struct cd_list		queue;
	int			free_threads;
	int			nr_tasks;
	int			shutdown;
};

struct pcs_file_job_conn
{
	struct pcs_process	*proc;

	int			nr_queues;
	int			nr_threads;	/* max total number of threads for all queues */
	int			cur_threads;
	unsigned int		seq;

	struct pcs_file_job_queue	queues[PCS_FILE_JOB_MAX_THREADS];
	pcs_thread_t			threads[PCS_FILE_JOB_MAX_THREADS];

	char		name[16];
};

PCS_API struct pcs_file_job * pcs_file_job_alloc(int (*fn)(void*), void * arg);
PCS_API void pcs_file_job_free(struct pcs_file_job *j);
PCS_API void pcs_file_job_init(struct pcs_file_job * j, int (*fn)(void*), void * arg);

PCS_API void pcs_file_job_submit(struct pcs_file_job_conn * io, struct pcs_file_job * j);
PCS_API void pcs_file_job_submit_hash(struct pcs_file_job_conn * io, struct pcs_file_job * j, unsigned int hash);

int pcs_file_job_conn_start(struct pcs_process * proc, const char *name, struct pcs_file_job_conn ** new_io);
void pcs_file_job_conn_stop(struct pcs_file_job_conn * io);
PCS_API void pcs_file_job_set_queues_threads(struct pcs_file_job_conn * io, int queues, int threads);
PCS_API int pcs_file_job_set_threads(struct pcs_file_job_conn * io, int new_threads);

#endif /* _PCS_FILE_JOB_H_ */
