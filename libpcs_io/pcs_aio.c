/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>

#include "pcs_config.h"
#include "pcs_types.h"
#include "pcs_aio.h"
#include "log.h"
#include "pcs_malloc.h"
#include "pcs_thread.h"
#include "jhash.h"
#include "pcs_event_ioconn.h"

#define AIO_TERMINATE_TIMEOUT (60*1000)

#if defined(HAVE_EVENTFD) && defined(HAVE_AIO)

static int translate_error(struct pcs_aioreq * req, int errval)
{
	switch (errval) {
	case -ENOSPC:
	case -EDQUOT:
		return PCS_ERR_NOSPACE;
	case -EFAULT:
		pcs_fatal("aio error: EFAULT");
	default:
		return PCS_ERR_IO;
	}
}

pcs_thread_ret_t aio_worker(void * arg)
{
	struct pcs_aio_worker * w = arg;
	struct pcs_aio * aio = container_of(w - w->idx, struct pcs_aio, workers[0]);

	pcs_thread_setname(pcs_thread_self(), "aio-worker");

	pthread_mutex_lock(&w->lock);
	while (1) {
		struct cd_list local_queue;

		if (cd_list_empty(&w->queue)) {
			if (w->shutdown)
				break;

			w->in_waiting++;
			pthread_cond_wait(&w->wake, &w->lock);
			w->in_waiting--;
			continue;
		}

		cd_list_init(&local_queue);
		cd_list_splice(&w->queue, &local_queue);
		pthread_mutex_unlock(&w->lock);

		while (!cd_list_empty(&local_queue)) {
			struct pcs_aioreq * req = cd_list_first_entry(&local_queue, struct pcs_aioreq, list);
			struct iocb * iocb = &req->iocb;
			int res;

			cd_list_del(&req->list);

			if (w->shutdown)
				res = -EAGAIN;
			else
				res = io_submit(aio->ctx, 1, &iocb);

			if (res < 0) {
				req->error = 0;

				if (res != -EAGAIN) {
					pcs_log(LOG_ERR, "io_submit error %d", res);
					req->error = translate_error(req, res);
				}

				/* In case of failure of io_submit, we return
				 * requests to special error_queue and manually
				 * send event to main thread.
				 */
				pthread_mutex_lock(&aio->error_lock);
				cd_list_add_tail(&req->list, &aio->error_queue);
				aio->error_count++;
				pthread_mutex_unlock(&aio->error_lock);

				pcs_event_ioconn_wakeup(aio->ioconn);
			} else {
				w->served++;
			}
		}

		pthread_mutex_lock(&w->lock);
	}
	pthread_mutex_unlock(&w->lock);
	return 0;
}

static void kick_same_aio(struct pcs_aio * aio)
{
	struct iocb * iocbs[aio->queued];
	struct pcs_aioreq * req;
	int n = 0;
	int i;

	cd_list_for_each_entry(struct pcs_aioreq, req, &aio->queue, list) {
		iocbs[n++] = &req->iocb;
	}

	if (n == 0)
		return;

	i = io_submit(aio->ctx, n, iocbs);
	if (i < 0) {
		int err = errno;

		if (i != -EAGAIN) {
			pcs_log(0, "io_submit error %d, errno = %d", i, err);
			while (!cd_list_empty(&aio->queue)) {
				req = cd_list_first_entry(&aio->queue,
							  struct pcs_aioreq, list);
				cd_list_del(&req->list);

				req->error = translate_error(req, i);
				req->complete(req);
				aio->queued--;
			}
		} else {
			BUG_ON(aio->pending == 0);
		}
		return;
	}

	aio->queued -= i;
	aio->pending += i;

	while (i > 0) {
		req = cd_list_first_entry(&aio->queue, struct pcs_aioreq, list);
		cd_list_del(&req->list);
		i--;
	}
}

/* We use _fixed_ hashing of client's iocontext to threads. No balancing.
 * The goal of executing aio from threads is to get proper CFQ iocontext,
 * if we switch between threads we would lose idle state.
 */

static inline struct pcs_aio_worker *
route(struct pcs_aio * aio, struct pcs_aioreq * req)
{
	u32 hash;

	hash = jhash3(req->client.val>>32, req->client.val&0xFFFFFFFF, req->iocontext, aio->salt);

	return aio->workers + (hash & (aio->threads - 1));
}

static void kick_threaded_aio(struct pcs_aio * aio)
{
	BUG_ON(!pcs_in_evloop());

	while (aio->pending < aio->acquired_reqs) {
		int do_wake;
		struct pcs_aio_worker * w;
		struct pcs_aioreq * req;

		if (cd_list_empty(&aio->queue))
			break;

		req = cd_list_first_entry(&aio->queue, struct pcs_aioreq, list);
		cd_list_del(&req->list);

		w = route(aio, req);

		if (!w->thr) {
			if (pcs_thread_create(&w->thr, NULL, aio_worker, (void*)w))
				pcs_fatal("Failed to create AIO thread");
		}

		do_wake = 0;
		pthread_mutex_lock(&w->lock);
		if (w->in_waiting && cd_list_empty(&w->queue))
			do_wake = 1;
		cd_list_add_tail(&req->list, &w->queue);
		pthread_mutex_unlock(&w->lock);

		aio->queued--;
		aio->pending++;

		if (do_wake)
			BUG_ON(pthread_cond_signal(&w->wake));
	}
}

static void kick_queue(struct pcs_aio * aio)
{
	if (aio->threads == 0)
		kick_same_aio(aio);
	else
		kick_threaded_aio(aio);
}

static void wait_requests(struct pcs_aio * aio, struct timespec * ts)
{
	struct io_event ev[aio->pending];
	int i, n;

	if (aio->error_count) {
		struct cd_list local_q;

		cd_list_init(&local_q);

		pthread_mutex_lock(&aio->error_lock);
		aio->error_count = 0;
		cd_list_splice(&aio->error_queue, &local_q);
		pthread_mutex_unlock(&aio->error_lock);

		while (!cd_list_empty(&local_q)) {
			struct pcs_aioreq * req = cd_list_first_entry(&local_q, struct pcs_aioreq, list);
			cd_list_del(&req->list);
			aio->pending--;

			if (req->error == 0 && aio->shutdown)
				req->error = PCS_ERR_NET_ABORT;

			if (req->error == 0) {
				cd_list_add_tail(&req->list, &aio->queue);
				aio->queued++;
			} else {
				req->complete(req);
			}
		}
	}

	n = io_getevents(aio->ctx, 1, aio->pending, ev, ts);
	if (n <= 0)
		return;

	for (i = 0; i < n; i++) {
		long err;
		struct iocb * ioc = ev[i].obj;
		struct pcs_aioreq * req = container_of(ioc, struct pcs_aioreq, iocb);

		req->error = 0;
		if (ev[i].res2)
			req->error = PCS_ERR_PROTOCOL;
		err = (long)ev[i].res;
		if (err < 0) {
			req->error = translate_error(req, err);
			pcs_log(0, "aio error %ld", err);
		} else if (err != (long)req->count) {
			pcs_log(0, "aio short io %ld, expected %ld, pos=%llu", err, (long)req->count,
				(unsigned long long)req->iocb.u.c.offset);
			if (!(req->flags & PCS_AIO_F_WRITE) && (req->flags & PCS_AIO_F_PAD)) {
				struct stat stb;

				/* Client AIO read/write are not synchronized with truncates,
				 * therefore this can happen.
				 * XXX however, this happens with fuse. Figure out why!
				 * It looks like client does not respect file size somewhere.
				 */
				if (!fstat(req->iocb.aio_fildes, &stb) &&
				    stb.st_size < req->iocb.u.c.offset + (off_t)req->count)
					memset(req->iocb.u.c.buf + err, 0, req->count - err);
				else
					req->error = PCS_ERR_IO;
			} else
				req->error = PCS_ERR_IO;
		}
		req->complete(req);
		aio->pending--;
	}
}

static void data_ready(void *priv)
{
	struct pcs_aio * aio = priv;
	struct timespec ts = (struct timespec){0 , 0};

	if (!aio->pending)
		return;

	wait_requests(aio, &ts);

	if (aio->queued)
		kick_queue(aio);
}
#else /* HAVE_EVENTFD */
static void kick_queue(struct pcs_aio * aio)
{
	pcs_job_wakeup(&aio->job);
}

static void aio_sync_job(void *data)
{
	struct pcs_aio * aio = (struct pcs_aio *)data;
	struct pcs_aioreq * req;
	ssize_t n;

	while (!cd_list_empty(&aio->queue)) {
		req = cd_list_first_entry(&aio->queue, struct pcs_aioreq, list);
		cd_list_del(&req->list);

restart:
		if (req->iocb.write)
			n = pwrite(req->iocb.fd, req->iocb.buf, req->iocb.count, req->iocb.offset);
		else
			n = pread(req->iocb.fd, req->iocb.buf, req->iocb.count, req->iocb.offset);

		if (n < 0 && errno == EINTR)
			goto restart;

		req->error = 0;
		if (n < 0) {
			req->error = PCS_ERR_IO;
			if (errno == ENOSPC || errno == EDQUOT)
				req->error = PCS_ERR_NOSPACE;
			else if (errno == EFAULT)
				pcs_fatal("aio error: EFAULT");
		} else if ((size_t)n != req->count)
			req->error = PCS_ERR_IO;

		req->complete(req);
		aio->queued--;
	}
}
#endif

struct pcs_aio * pcs_aio_init(struct pcs_process * proc, int threads)
{
	int i;
	struct pcs_aio * aio;

#if defined(HAVE_EVENTFD) && defined(HAVE_AIO)
	if (threads & (threads - 1))
		return NULL;
#else
	threads = 0;
#endif

	aio = pcs_malloc(sizeof(struct pcs_aio) + threads * sizeof(struct pcs_aio_worker));
	if (!aio)
		return NULL;

#if defined(HAVE_EVENTFD) && defined(HAVE_AIO)
	memset(&aio->ctx, 0, sizeof(aio->ctx));
#endif

	cd_list_init(&aio->queue);
	aio->queued = 0;
	aio->shutdown = 0;

	aio->max_threads = threads;
	aio->threads = 0;
	aio->salt = get_real_time_us();

	pthread_mutex_init(&aio->error_lock, NULL);
	cd_list_init(&aio->error_queue);
	aio->error_count = 0;

	aio->pending = 0;

	for (i = 0; i < threads; i++) {
		struct pcs_aio_worker * w = aio->workers + i;

		memset(w, 0, sizeof(*w));
		cd_list_init(&w->queue);
		w->idx = i;
		pthread_mutex_init(&w->lock, NULL);
		pthread_cond_init(&w->wake, NULL);
	}
	return aio;
}

int pcs_aio_start(struct pcs_process * proc, struct pcs_aio * aio)
{
#if defined(HAVE_EVENTFD) && defined(HAVE_AIO)
	int maxreqs;
	int err;

	maxreqs = PCS_AIO_MAXREQS;
	while (maxreqs > 0) {
		if ((err = io_setup(maxreqs, &aio->ctx)) == 0)
			break;
		maxreqs /= 2;
		if (err != -EAGAIN)
			maxreqs = 0;
	}

	if (maxreqs == 0) {
		errno = -err;
		return -1;
	}
	aio->acquired_reqs = maxreqs;

	if ((err = pcs_event_ioconn_init(proc, &aio->ioconn, data_ready, aio))) {
		errno = -err;
		return -1;
	}
#else
	pcs_job_init(proc, &aio->job, aio_sync_job, aio);
#endif
	return 0;
}

void pcs_aioreq_submit(struct pcs_aio * aio, struct pcs_aioreq * req)
{
	BUG_ON(!pcs_in_evloop());

#if defined(HAVE_EVENTFD) && defined(HAVE_AIO)
	io_set_eventfd(&req->iocb, aio->ioconn->send_event_fd);
#endif

	cd_list_add_tail(&req->list, &aio->queue);
	aio->queued++;

	kick_queue(aio);
}

void pcs_aioreq_init(struct pcs_aioreq * req)
{
	cd_list_init(&req->list);
}

int pcs_aio_set_threads(struct pcs_aio * aio, int new_threads)
{
	int i;
	int old_threads;
	int threads = new_threads;

	if (new_threads > aio->max_threads)
		return -EINVAL;

	if (threads) {
		threads = 1;

		while ((threads << 1) < new_threads)
			threads <<= 1;
	}

	old_threads = aio->threads;
	aio->threads = threads;

	for (i = threads; i < old_threads; i++) {
		struct pcs_aio_worker * w = aio->workers + i;

		if (!w->thr)
			continue;

		pthread_mutex_lock(&w->lock);
		w->shutdown = 1;
		pthread_cond_signal(&w->wake);
		pthread_mutex_unlock(&w->lock);
	}

	/* Not cool. But the threads can block only in io_submit.
	 * We used to consider this operation as non-blocking, so it is not too bad.
	 */
	for (i = threads; i < old_threads; i++) {
		int err;
		struct pcs_aio_worker * w = aio->workers + i;

		if (!w->thr)
			continue;

		err = pcs_thread_timedjoin(w->thr, NULL, AIO_TERMINATE_TIMEOUT);
		if (err)
			pcs_fatal("failed to join aio thread, err %d(%s)", err, strerror(err));

		w->thr = 0;
		w->shutdown = 0;
		TRACE("thread %d closed: served %d", w->idx, w->served);
		w->served = 0;
	}
	return 0;
}

int pcs_aio_deinit(struct pcs_aio * aio)
{
	/* Not implemented */
	BUG();
	return -1;
}
