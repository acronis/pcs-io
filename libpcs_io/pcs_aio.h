/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_AIO_H_
#define _PCS_AIO_H_ 1

#include "pcs_config.h"
#include "pcs_process.h"
#include "pcs_thread.h"
#include "pcs_error.h"

#if defined(HAVE_AIO) && defined(HAVE_EVENTFD)
#include <libaio.h>
#endif

#define PCS_AIO_MAXREQS	128

#if !defined(HAVE_AIO) || !defined(HAVE_EVENTFD)
/* for AIO emulation */
struct iocb {
	int fd;
	int write;		/* 0 == read */
	void *buf;
	size_t count;
	long long offset;
};
#endif

struct pcs_aioreq
{
	struct cd_list	list;
	struct iocb	iocb;
	u64		pos;
	size_t		count;
	int		error;
	PCS_NODE_ID_T	client;
	u32		iocontext;
	int		flags;
	void		*priv;
	void		(*complete)(struct pcs_aioreq *);
};

#define PCS_AIO_F_WRITE		1
#define PCS_AIO_F_PAD		2

struct pcs_aio_worker
{
	struct cd_list		queue;
	short			idx;
	unsigned short		shutdown;
	int			in_waiting;
	pcs_thread_t		thr;
	pthread_mutex_t		lock;
	pthread_cond_t		wake;

	int			served;
};

struct pcs_aio
{
	struct cd_list		queue;
	int			queued;

	int			acquired_reqs;
	int			shutdown;
	int			max_threads;
	int			threads;
#if defined(HAVE_EVENTFD) && defined(HAVE_AIO)
	struct pcs_event_ioconn	*ioconn;
	io_context_t		ctx;
#else
	struct pcs_job		job;
#endif

	pthread_mutex_t		error_lock;
	struct cd_list		error_queue;
	int			error_count;

	int			pending;

	u32			salt;

	struct pcs_aio_worker	workers[0];
};

#if !defined(HAVE_AIO) || !defined(HAVE_EVENTFD)
static inline void io_prep(struct iocb *iocb, int write, int fd, void *buf, size_t count, long long offset)
{
	iocb->write = write;
	iocb->fd = fd;
	iocb->buf = buf;
	iocb->count = count;
	iocb->offset = offset;
}

static inline void io_prep_pread(struct iocb *iocb, int fd, void *buf, size_t count, long long offset)
{
	io_prep(iocb, 0, fd, buf, count, offset);
}

static inline void io_prep_pwrite(struct iocb *iocb, int fd, void *buf, size_t count, long long offset)
{
	io_prep(iocb, 1, fd, buf, count, offset);
}
#endif

static inline void pcs_aio_pread(struct pcs_aioreq *req, int fd, void *buf,
				 size_t count, long long offset)
{
	req->pos = offset;
	req->count = count;
	req->flags = 0;
	io_prep_pread(&req->iocb, fd, buf, count, offset);
}

static inline void pcs_aio_pwrite(struct pcs_aioreq *req, int fd, void *buf,
				 size_t count, long long offset)
{
	req->pos = offset;
	req->count = count;
	req->flags = PCS_AIO_F_WRITE;
	io_prep_pwrite(&req->iocb, fd, buf, count, offset);
}

#if 0	/* not used now and implemented on Linux only */
static inline void pcs_aio_preadv(struct pcs_aioreq *req, int fd, struct iovec *iov,
				  int iovcnt, size_t count, long long offset)
{
	req->count = count;
	io_prep_preadv(&req->iocb, fd, iov, iovcnt, offset);
}

static inline void pcs_aio_pwritev(struct pcs_aioreq *req, int fd, struct iovec *iov,
				  int iovcnt, size_t count, long long offset)
{
	req->count = count;
	io_prep_pwritev(&req->iocb, fd, iov, iovcnt, offset);
}
#endif

void pcs_aioreq_init(struct pcs_aioreq *);
void pcs_aioreq_free(struct pcs_aio *, struct pcs_aioreq *);
void pcs_aioreq_submit(struct pcs_aio *, struct pcs_aioreq *);

struct pcs_aio * pcs_aio_init(struct pcs_process *, int threads);
int pcs_aio_start(struct pcs_process * proc, struct pcs_aio * aio);
int pcs_aio_deinit(struct pcs_aio * aio);
int pcs_aio_set_threads(struct pcs_aio * aio, int threads);

#endif /* _PCS_AIO_H_ */
