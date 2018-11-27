/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_sync_ioreq.h"
#include "pcs_sync_io.h"
#include "pcs_malloc.h"
#include "pcs_errno.h"
#include "bug.h"
#include "log.h"

#include <limits.h>

#define SYNCIO_TERMINATE_TIMEOUT (60*1000)

static void data_ready(void *arg)
{
	struct cd_list local_q;
	struct pcs_sync_io *io = arg;

	cd_list_init(&local_q);
	pthread_mutex_lock(&io->out_mutex);
	cd_list_splice(&io->out_queue, &local_q);
	pthread_mutex_unlock(&io->out_mutex);

	while (!cd_list_empty(&local_q)) {
		struct pcs_sync_ioreq * req = cd_list_first_entry(&local_q,
							      struct pcs_sync_ioreq, list);
		cd_list_del(&req->list);
		req->complete(req);
		io->queued--;
	}
}

void pcs_sync_io_stop(struct pcs_sync_io * io)
{
	int err;

	pthread_mutex_lock(&io->in_mutex);

	io->shutdown = 1;

	BUG_ON(!pcs_in_evloop() && pcs_process_is_running(io->proc));
	BUG_ON(io->queued);

	pthread_cond_signal(&io->in_wake);
	pthread_mutex_unlock(&io->in_mutex);

	err = pcs_thread_timedjoin(io->thr, NULL, SYNCIO_TERMINATE_TIMEOUT);
	if (err)
		pcs_fatal("failed to join sync io thread, err %d(%s)", err, strerror(err));

#ifndef FSYNC_IS_BARRIER
	pthread_cond_signal(&io->fsync_wake);
	err = pcs_thread_timedjoin(io->fsync_thr, NULL, SYNCIO_TERMINATE_TIMEOUT);
	if (err)
		pcs_fatal("failed to join fsync io thread, err %d(%s)", err, strerror(err));

	pthread_mutex_destroy(&io->fsync_mutex);
	pthread_cond_destroy(&io->fsync_wake);
#endif

	pthread_mutex_destroy(&io->in_mutex);
	pthread_mutex_destroy(&io->out_mutex);
	pthread_cond_destroy(&io->in_wake);

	pcs_event_ioconn_close(io->event);
	pcs_free(io);
}

static int do_sync_fd(struct pcs_sync_io * io, struct pcs_sync_ioreq * sreq, struct cd_list * q, struct cd_list * comp_queue)
{
	struct pcs_sync_ioreq * req, * next;
	int err = 0;
	int res = 0;
	int count = 0;

	if (sreq->flags & PCS_SYNC_IO_FSYNC)
		err = pcs_sync_fsync(sreq->fd);
	else if (sreq->flags & PCS_SYNC_IO_FDATASYNC)
		err = pcs_sync_fdatasync(sreq->fd);

	if (err < 0) {
		TRACE("fsync error %d", -err);
		res = err;
		err = errno_enospc(-err) ? PCS_ERR_NOSPACE : PCS_ERR_IO;
	}

	cd_list_for_each_entry_safe(struct pcs_sync_ioreq, req, next, q, list) {
		if (req->fd != sreq->fd)
			continue;

		cd_list_move_tail(&req->list, comp_queue);
		if (req->flags & (PCS_SYNC_IO_FSYNC|PCS_SYNC_IO_FDATASYNC))
			count++;

		if (err && !req->error)
			req->error = err;
		if (res && !req->res)
			req->res = res;
	}
	return count;
}

static pcs_thread_ret_t io_process(void * arg)
{
	struct pcs_sync_io * io = (struct pcs_sync_io *)arg;

	pcs_thread_setname(pcs_thread_self(), "syncio-io");

	pthread_mutex_lock(&io->in_mutex);
	while (!io->shutdown) {
		struct cd_list local_queue;
		struct cd_list comp_queue;
#ifndef FSYNC_IS_BARRIER
		int fsync_wake = 0;
#endif

		if (cd_list_empty(&io->in_queue)) {
			io->in_waiting++;
			pthread_cond_wait(&io->in_wake, &io->in_mutex);
			io->in_waiting--;
			continue;
		}

		cd_list_init(&comp_queue);

		cd_list_init(&local_queue);
		cd_list_splice(&io->in_queue, &local_queue);
		pthread_mutex_unlock(&io->in_mutex);

		while (!cd_list_empty(&local_queue)) {
			struct pcs_sync_ioreq * req = cd_list_first_entry(&local_queue,
									  struct pcs_sync_ioreq, list);
			req->error = 0;
			if (req->flags & PCS_SYNC_IO_READ) {
				BUG_ON(req->count > INT_MAX);
				req->res = pcs_sync_nread(req->fd, req->pos, req->buf, (int)req->count);
				if (req->res != (int)req->count) {
					if (!(req->res >= 0 && (req->flags & PCS_SYNC_IO_READ_AVAIL))) {
						req->res = -EIO;
						req->error = PCS_ERR_IO;
					}
				}
			} else if (req->flags & PCS_SYNC_IO_WRITE) {
				req->res = 0;
				if (req->count) {
					BUG_ON(req->count > INT_MAX);
					req->res = pcs_sync_nwrite(req->fd, req->pos, req->buf, (int)req->count);
					if (req->res > 0 && (req->flags & PCS_SYNC_IO_FLUSH_ASYNC)) {
#ifdef HAVE_SYNC_FILE_RANGE
						sync_file_range(req->fd, req->pos, req->res, SYNC_FILE_RANGE_WRITE);
#endif
					}
				}
			} else if (req->flags & (PCS_SYNC_IO_FLUSH|PCS_SYNC_IO_FLUSH_ASYNC)) {
#ifdef HAVE_SYNC_FILE_RANGE
				int sflags = SYNC_FILE_RANGE_WRITE;
				if (req->flags & PCS_SYNC_IO_FLUSH)
					sflags |= SYNC_FILE_RANGE_WAIT_AFTER;
				req->res = sync_file_range(req->fd, req->pos, req->count, sflags);
				req->res = (req->res < 0) ? -errno : 0;
#endif
			} else if (req->flags & PCS_SYNC_IO_TRUNCATE) {
				req->res = pcs_sync_ftruncate(req->fd, req->pos);
			}
			if (req->res < 0) {
				if (req->res == -EFAULT)
					pcs_fatal("sync io error: EFAULT");
				req->error = errno_enospc(-req->res) ? PCS_ERR_NOSPACE : PCS_ERR_IO;
			}

			if (req->error) {
				TRACE("IO error op=%x sz=%ld pos=%lld ret=%ld", req->flags, (long)req->count, req->pos, (long)req->res);
			}

			if (req->flags & PCS_SYNC_IO_WRITE && !(req->flags & PCS_SYNC_IO_NOSYNCWAIT)) {
				if (req->flags & (PCS_SYNC_IO_FSYNC|PCS_SYNC_IO_FDATASYNC)) {
#ifdef FSYNC_IS_BARRIER
					cd_list_move_tail(&req->list, &io->fsync_queue);
					do_sync_fd(io, req, &io->fsync_queue, &comp_queue);
#else
					pthread_mutex_lock(&io->fsync_mutex);
					cd_list_move_tail(&req->list, &io->fsync_queue);
					io->fsync_count++;
					fsync_wake = 1;
					pthread_mutex_unlock(&io->fsync_mutex);
#endif
				} else {
					cd_list_move_tail(&req->list, &io->fsync_queue);
				}
			} else {
				cd_list_move_tail(&req->list, &comp_queue);
			}

		}

#ifndef FSYNC_IS_BARRIER
		if (fsync_wake)
			pthread_cond_signal(&io->fsync_wake);
#endif

		if (!cd_list_empty(&comp_queue)) {
			pthread_mutex_lock(&io->out_mutex);
			cd_list_splice(&comp_queue, io->out_queue.prev);
			pthread_mutex_unlock(&io->out_mutex);

			pcs_event_ioconn_wakeup(io->event);
		}

		pthread_mutex_lock(&io->in_mutex);

	}
	pthread_mutex_unlock(&io->in_mutex);
	return 0;
}

#ifndef FSYNC_IS_BARRIER

static pcs_thread_ret_t fsync_process(void * arg)
{
	struct pcs_sync_io * io = (struct pcs_sync_io *)arg;

	pcs_thread_setname(pcs_thread_self(), "syncio-fsync");

	pthread_mutex_lock(&io->fsync_mutex);
	while (!io->shutdown) {
		struct cd_list local_queue;
		struct cd_list comp_queue;
		int count = 0;

		if (io->fsync_count == 0) {
			pthread_cond_wait(&io->fsync_wake, &io->fsync_mutex);
			continue;
		}

		cd_list_init(&comp_queue);

		cd_list_init(&local_queue);
		cd_list_splice(&io->fsync_queue, &local_queue);
		pthread_mutex_unlock(&io->fsync_mutex);

		for (;;) {
			struct pcs_sync_ioreq * req, * sreq;

			sreq = NULL;
			cd_list_for_each_entry_reverse(struct pcs_sync_ioreq, req, &local_queue, list) {
				if (req->flags & (PCS_SYNC_IO_FSYNC|PCS_SYNC_IO_FDATASYNC)) {
					sreq = req;
					break;
				}
			}

			if (sreq == NULL)
				break;

			count += do_sync_fd(io, sreq, &local_queue, &comp_queue);
		}

		if (!cd_list_empty(&comp_queue)) {
			pthread_mutex_lock(&io->out_mutex);
			cd_list_splice(&comp_queue, io->out_queue.prev);
			pthread_mutex_unlock(&io->out_mutex);

			send_event(io);
		}

		pthread_mutex_lock(&io->fsync_mutex);
		io->fsync_count -= count;
		cd_list_splice(&local_queue, &io->fsync_queue);
	}
	pthread_mutex_unlock(&io->in_mutex);
	return 0;
}

#endif

static struct pcs_sync_io * pcs_sync_io_alloc(void)
{
	struct pcs_sync_io * io;

	io = pcs_malloc(sizeof(struct pcs_sync_io));
	if (!io)
		return NULL;

	io->shutdown = 0;

	pthread_mutex_init(&io->in_mutex, NULL);
	pthread_cond_init(&io->in_wake, NULL);
	cd_list_init(&io->in_queue);
	io->in_waiting = 0;

	cd_list_init(&io->fsync_queue);
#ifndef FSYNC_IS_BARRIER
	pthread_mutex_init(&io->fsync_mutex, NULL);
	pthread_cond_init(&io->fsync_wake, NULL);
	io->fsync_count = 0;
#endif

	pthread_mutex_init(&io->out_mutex, NULL);
	cd_list_init(&io->out_queue);
	io->queued = 0;

	return io;
}

int pcs_sync_io_start(struct pcs_process * proc, struct pcs_sync_io ** new_io)
{
	struct pcs_sync_io * io;
	int err;

	io = pcs_sync_io_alloc();
	if (!io)
		return -ENOMEM;

	io->proc = proc;

	if ((err = pcs_event_ioconn_init(proc, &io->event, data_ready, io)))
		goto out_errno;

	if (pcs_thread_create(&io->thr, NULL, io_process, (void*)io))
		goto out_close;

#ifndef FSYNC_IS_BARRIER
	if (pcs_thread_create(&io->fsync_thr, NULL, fsync_process, (void*)io)) {
		int serr = errno;
		io->shutdown = 1;
		pthread_cond_signal(&io->in_wake);
		err = pcs_thread_timedjoin(io->thr, NULL, SYNCIO_TERMINATE_TIMEOUT);
		if (err)
			pcs_fatal("failed to join sync io thread, err %d(%s)", err, strerror(err));
		errno = serr;
		goto out_close;
	}
#endif

	*new_io = io;
	return 0;

out_close:
	err = -errno;
	pcs_event_ioconn_close(io->event);

out_errno:
	pcs_free(io);
	return err;
}

void pcs_sync_ioreq_submit(struct pcs_sync_io * io, struct pcs_sync_ioreq * req)
{
	int do_wake = 0;

	pthread_mutex_lock(&io->in_mutex);
	if (io->in_waiting && cd_list_empty(&io->in_queue))
		do_wake = 1;
	cd_list_add_tail(&req->list, &io->in_queue);
	pthread_mutex_unlock(&io->in_mutex);

	BUG_ON(!pcs_in_evloop() && pcs_process_is_running(io->proc));
	io->queued++;

	if (do_wake)
		BUG_ON(pthread_cond_signal(&io->in_wake));
}

struct pcs_sync_ioreq * pcs_sync_ioreq_alloc(void)
{
	struct pcs_sync_ioreq *res;

	res = pcs_malloc(sizeof(*res));
	if (!res)
		return res;

	pcs_sync_ioreq_init(res);
	return res;
}

void pcs_sync_ioreq_init(struct pcs_sync_ioreq * req)
{
	memset(req, 0, sizeof(*req));
	cd_list_init(&req->list);
}

void pcs_sync_ioreq_free(struct pcs_sync_ioreq *req)
{
	pcs_free(req);
}
