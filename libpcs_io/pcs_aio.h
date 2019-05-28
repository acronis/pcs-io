/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_AIO_H_
#define _PCS_AIO_H_ 1

#include "pcs_config.h"
#include "pcs_process.h"
#include "pcs_thread.h"
#include "pcs_error.h"

#include <string.h>

#ifdef HAVE_AIO
#define _LINUX_MOUNT_H	/* workaround incompatiblity with <sys/mount.h> */
#include <linux/aio_abi.h>
#endif

#define PCS_AIO_MAXREQS	128

struct pcs_aioreq
{
	struct cd_list	list;
#ifdef HAVE_AIO
	struct iocb	iocb;
#else
	int		fd;
	void		*buf;
#endif
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
#ifdef HAVE_AIO
	struct pcs_event_ioconn	*ioconn;
	aio_context_t		ctx;
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

static inline void pcs_aio_pread(struct pcs_aioreq *req, int fd, void *buf,
				 size_t count, long long offset)
{
	req->pos = offset;
	req->count = count;
	req->flags = 0;
#ifdef HAVE_AIO
	memset(&req->iocb, 0, sizeof(req->iocb));
	req->iocb.aio_lio_opcode = IOCB_CMD_PREAD;
	req->iocb.aio_fildes = fd;
	req->iocb.aio_buf = (u64)buf;
	req->iocb.aio_nbytes = count;
	req->iocb.aio_offset = offset;
#else
	req->fd = fd;
	req->buf = buf;
#endif
}

static inline void pcs_aio_pwrite(struct pcs_aioreq *req, int fd, void *buf,
				 size_t count, long long offset)
{
	req->pos = offset;
	req->count = count;
	req->flags = PCS_AIO_F_WRITE;
#ifdef HAVE_AIO
	memset(&req->iocb, 0, sizeof(req->iocb));
	req->iocb.aio_lio_opcode = IOCB_CMD_PWRITE;
	req->iocb.aio_fildes = fd;
	req->iocb.aio_buf = (u64)buf;
	req->iocb.aio_nbytes = count;
	req->iocb.aio_offset = offset;
#else
	req->fd = fd;
	req->buf = buf;
#endif
}

void pcs_aioreq_init(struct pcs_aioreq *);
void pcs_aioreq_free(struct pcs_aio *, struct pcs_aioreq *);
void pcs_aioreq_submit(struct pcs_aio *, struct pcs_aioreq *);

struct pcs_aio * pcs_aio_init(struct pcs_process *, int threads);
int pcs_aio_start(struct pcs_process * proc, struct pcs_aio * aio);
int pcs_aio_deinit(struct pcs_aio * aio);
int pcs_aio_set_threads(struct pcs_aio * aio, int threads);

#endif /* _PCS_AIO_H_ */
