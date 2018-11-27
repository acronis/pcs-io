/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_SYNC_IOREQ_H_
#define _PCS_SYNC_IOREQ_H_ 1

#include <pthread.h>
#include "pcs_process.h"
#include "pcs_thread.h"
#include "pcs_error.h"
#include "pcs_event_ioconn.h"

#define FSYNC_IS_BARRIER 1

struct pcs_sync_ioreq;
typedef void (*pcs_sync_io_cb)(struct pcs_sync_ioreq *);

struct pcs_sync_ioreq
{
	struct cd_list		list;
	char			*buf;
	size_t			count;
	unsigned long long	pos;
	pcs_fd_t		fd;
	int			flags;
	int			res;
	pcs_err_t		error;
	void			*priv;
	pcs_sync_io_cb		complete;
};

#define PCS_SYNC_IO_READ	1

#define PCS_SYNC_IO_WRITE	2	/* write completes after FSYNC/FDATASYNC or immedeately if NOSYNCWAIT is set */
#define PCS_SYNC_IO_NOSYNCWAIT	4
#define PCS_SYNC_IO_FSYNC	8
#define PCS_SYNC_IO_FDATASYNC	16

#define PCS_SYNC_IO_FLUSH	32	/* flush kernel writeback using sync_file_range, doesn't send device barrier */
#define PCS_SYNC_IO_TRUNCATE	64
#define PCS_SYNC_IO_FLUSH_ASYNC	128
#define PCS_SYNC_IO_READ_AVAIL  0x10000 /* Read available data and update count accordingly */

struct pcs_sync_io
{
	struct pcs_process	*proc;
	struct pcs_event_ioconn	*event;

	int			shutdown;
	int			queued;

	pcs_thread_t		thr;

	/* Incoming queue */
	struct cd_list		in_queue;
	pthread_mutex_t		in_mutex;
	pthread_cond_t		in_wake;
	int			in_waiting;

	struct cd_list		fsync_queue;
#ifndef FSYNC_IS_BARRIER
	pthread_mutex_t		fsync_mutex;
	pthread_cond_t		fsync_wake;
	int			fsync_count;
	pcs_thread_t		fsync_thr;
#endif

	/* Completion queue */
	struct cd_list		out_queue;
	pthread_mutex_t		out_mutex;
};

struct pcs_sync_ioreq * pcs_sync_ioreq_alloc(void);
void pcs_sync_ioreq_init(struct pcs_sync_ioreq *);
void pcs_sync_ioreq_free(struct pcs_sync_ioreq *);

static inline void pcs_sync_ioreq_pread(struct pcs_sync_ioreq *req, pcs_fd_t fd, void *buf,
				     size_t count, long long offset)
{
	req->buf = (char *)buf;
	req->count = count;
	req->pos = offset;
	req->fd = fd;
	req->flags = PCS_SYNC_IO_READ;
}

static inline void pcs_sync_ioreq_pwrite(struct pcs_sync_ioreq *req, pcs_fd_t fd, void const *buf,
				      size_t count, long long offset, int sync)
{
	req->buf = (char *)buf;
	req->count = count;
	req->pos = offset;
	req->fd = fd;
	req->flags = PCS_SYNC_IO_WRITE | sync;
}

static inline void pcs_sync_ioreq_fsync(struct pcs_sync_ioreq *req, pcs_fd_t fd)
{
	req->count = 0;
	req->fd = fd;
	req->flags = PCS_SYNC_IO_WRITE | PCS_SYNC_IO_FSYNC;
}

static inline void pcs_sync_ioreq_fdatasync(struct pcs_sync_ioreq *req, pcs_fd_t fd)
{
	req->count = 0;
	req->fd = fd;
	req->flags = PCS_SYNC_IO_WRITE | PCS_SYNC_IO_FDATASYNC;
}

static inline void pcs_sync_ioreq_flush(struct pcs_sync_ioreq *req, pcs_fd_t fd,
				      size_t count, long long offset)
{
	req->count = count;
	req->pos = offset;
	req->fd = fd;
	req->flags = PCS_SYNC_IO_FLUSH;
}

static inline void pcs_sync_ioreq_async_flush(struct pcs_sync_ioreq *req, pcs_fd_t fd,
					 size_t count, long long offset)
{
	req->count = count;
	req->pos = offset;
	req->fd = fd;
	req->flags = PCS_SYNC_IO_FLUSH_ASYNC;
}

static inline void pcs_sync_ioreq_truncate(struct pcs_sync_ioreq *req, pcs_fd_t fd, long long offset)
{
	req->pos = offset;
	req->fd = fd;
	req->flags = PCS_SYNC_IO_TRUNCATE;
}

void pcs_sync_ioreq_submit(struct pcs_sync_io *, struct pcs_sync_ioreq *);

int pcs_sync_io_start(struct pcs_process * proc, struct pcs_sync_io ** new_io);
void pcs_sync_io_stop(struct pcs_sync_io * io);

#endif /* _PCS_SYNC_IO_H_ */
