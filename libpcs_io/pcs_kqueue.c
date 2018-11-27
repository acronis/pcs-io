/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_poll.h"

#ifdef HAVE_KQUEUE

#include "pcs_process.h"
#include "pcs_ioconn.h"
#include "pcs_signal.h"
#include "pcs_co_io.h"
#include "pcs_co_locks.h"
#include "bug.h"
#include "log.h"

#include <errno.h>
#include <unistd.h>

int pcs_poll_ctl(struct pcs_process *proc, struct pcs_ioconn *conn)
{
	struct kevent ev[2];
	int nr = 0;

	if ((conn->actual_mask ^ conn->next_mask) & POLLIN) {
		ev[nr].ident = conn->fd;
		ev[nr].filter = EVFILT_READ;
		ev[nr].flags = (conn->next_mask & EPOLLET ? EV_CLEAR : 0) | (conn->next_mask & POLLIN ? EV_ADD : EV_DELETE);
		ev[nr].fflags = 0;
		ev[nr].data = 0;
		ev[nr].udata = conn;
		nr++;
	}
	if ((conn->actual_mask ^ conn->next_mask) & POLLOUT) {
		ev[nr].ident = conn->fd;
		ev[nr].filter = EVFILT_WRITE;
		ev[nr].flags = (conn->next_mask & EPOLLET ? EV_CLEAR : 0) | (conn->next_mask & POLLOUT ? EV_ADD : EV_DELETE);
		ev[nr].fflags = 0;
		ev[nr].data = 0;
		ev[nr].udata = conn;
		nr++;
	}
	return kevent(proc->kqueue, ev, nr, NULL, 0, NULL);
}

void pcs_poll_wait(struct pcs_evloop *evloop, int timeout)
{
	BUG_ON(evloop->nr_events > 0);

	struct timespec ts = {.tv_sec = timeout / 1000, .tv_nsec = (timeout % 1000) * 1000000};
	evloop->nr_events = kevent(evloop->proc->kqueue, NULL, 0, evloop->events, PCS_MAX_EVENTS_NR, &ts);
}

static void process_ioconn_event(struct kevent *ev)
{
	struct pcs_ioconn *conn = ev->udata;

	switch (ev->filter) {
	case EVFILT_READ:
		conn->data_ready(conn);
		if (ev->flags & EV_EOF)
			conn->error_report(conn);
		pcs_ioconn_schedule(conn);
		break;

	case EVFILT_WRITE:
		conn->write_space(conn);
		if (ev->flags & EV_EOF)
			conn->error_report(conn);
		pcs_ioconn_schedule(conn);
		break;

	case EVFILT_USER:
		conn->data_ready(conn);
		break;

	case EVFILT_SIGNAL:
		pcs_signal_call_handler(conn, ev->ident);
		break;

	default:
		BUG();
	}
}

static void process_co_file_event(struct kevent *ev)
{
	struct pcs_co_file *file = (struct pcs_co_file *)((ULONG_PTR)ev->udata & ~(ULONG_PTR)1);

	switch (ev->filter) {
	case EVFILT_READ:
		pcs_co_event_signal(&file->reader.ev);
		break;

	case EVFILT_WRITE:
		pcs_co_event_signal(&file->writer.ev);
		break;

	default:
		BUG();
	}
}

void pcs_poll_process_events(struct pcs_evloop *evloop)
{
	int i;
	for (i = 0; i < evloop->nr_events; i++) {
		struct kevent *ev = &evloop->events[i];

		if ((ULONG_PTR)ev->udata & 1)
			process_co_file_event(ev);
		else
			process_ioconn_event(ev);
	}

	evloop->nr_events = 0;
}

int pcs_poll_init(struct pcs_process *proc)
{
	proc->kqueue = kqueue();
	if (proc->kqueue < 0)
		return -errno;
	return 0;
}

void pcs_poll_fini(struct pcs_process *proc)
{
	if (proc->kqueue >= 0)
		close(proc->kqueue);
	proc->kqueue = -1;
}

void pcs_poll_file_init(struct pcs_co_file *file)
{
}

void pcs_poll_file_fini(struct pcs_co_file *file)
{
}

void pcs_poll_file_begin(struct pcs_co_file *file, int mask)
{
	struct kevent ev = {.ident = file->fd, .flags = EV_ADD|EV_ONESHOT, .udata = (void *)((ULONG_PTR)file | 1)};

	switch (mask) {
	case POLLIN:
		ev.filter = EVFILT_READ;
		break;

	case POLLOUT:
		ev.filter = EVFILT_WRITE;
		break;

	default:
		BUG();
	}

	if ((kevent(pcs_current_proc->kqueue, &ev, 1, NULL, 0, NULL))) {
		pcs_log_syserror(LOG_ERR, errno, "pcs_poll_file_begin: kevent failed");
		BUG();
	}
}

#endif /* HAVE_KQUEUE */
