/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_poll.h"

#ifdef HAVE_EPOLL

#include "pcs_process.h"
#include "pcs_ioconn.h"
#include "pcs_co_io.h"
#include "pcs_co_locks.h"
#include "bug.h"
#include "log.h"

#include <errno.h>
#include <unistd.h>

int pcs_poll_ctl(struct pcs_process *proc, struct pcs_ioconn *conn)
{
	int op;
	if (conn->next_mask == 0)
		op = EPOLL_CTL_DEL;
	else if (conn->actual_mask == 0)
		op = EPOLL_CTL_ADD;
	else
		op = EPOLL_CTL_MOD;

	struct epoll_event ev = {.events = conn->next_mask, .data = {.ptr = conn}};
	return epoll_ctl(proc->epollfd, op, conn->fd, &ev);
}

void pcs_poll_wait(struct pcs_evloop *evloop, int timeout)
{
	BUG_ON(evloop->nr_events > 0);

	for (;;) {
		evloop->nr_events = epoll_wait(evloop->proc->epollfd, evloop->events, PCS_MAX_EVENTS_NR, timeout);
		if (evloop->nr_events >= 0 || errno != EINTR)
			break;

		/* Optimization for the idle case.
		 * Profiler timer is not disabled by default as it is quite expensive operation.
		 * So signal still kicks out us of epoll and disables itself, then we get EINTR and need to restart with new timeout cause no fds are ready.
		 * if we don't restart, timer will be re-armed in event loop and we will never sleep more then 10ms even when 100% idle */
		timeout = get_timers_timeout(&evloop->timers);
	}
}

static void process_ioconn_event(struct epoll_event *ev)
{
	struct pcs_ioconn *conn = ev->data.ptr;
	int events = ev->events;

	if (likely(events & POLLIN))
		conn->data_ready(conn);

	if (unlikely(events & POLLOUT))
		conn->write_space(conn);

	if (unlikely(events & (POLLERR|POLLHUP|POLLNVAL|POLLRDHUP)))
		conn->error_report(conn);

	pcs_ioconn_schedule(conn);
}

static void process_co_file_event(struct epoll_event *ev)
{
	struct pcs_co_file *file = (struct pcs_co_file *)((ULONG_PTR)ev->data.ptr & ~(ULONG_PTR)1);
	int events = ev->events;

	if (events & (POLLERR|POLLHUP|POLLNVAL|POLLRDHUP))
		pcs_atomic32_or(&file->err_mask, events);

	if (events & (POLLIN|POLLERR|POLLHUP|POLLNVAL|POLLRDHUP))
		pcs_co_event_signal(&file->reader.ev);

	if (events & (POLLOUT|POLLERR|POLLHUP|POLLNVAL))
		pcs_co_event_signal(&file->writer.ev);
}

void pcs_poll_process_events(struct pcs_evloop *evloop)
{
	int i;
	for (i = 0; i < evloop->nr_events; i++) {
		struct epoll_event *ev = &evloop->events[i];

		if ((ULONG_PTR)ev->data.ptr & 1)
			process_co_file_event(ev);
		else
			process_ioconn_event(ev);
	}

	evloop->nr_events = 0;
}

int pcs_poll_init(struct pcs_process *proc)
{
#ifdef EPOLL_CLOEXEC
	proc->epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (proc->epollfd < 0)
		return -errno;
#else
	proc->epollfd = epoll_create(1);	/* size is ignored */
	if (proc->epollfd < 0)
		return -errno;

	fcntl(proc->epollfd, F_SETFD, FD_CLOEXEC);
#endif
	return 0;
}

void pcs_poll_fini(struct pcs_process *proc)
{
	if (proc->epollfd >= 0)
		close(proc->epollfd);
	proc->epollfd = -1;
}

void pcs_poll_file_init(struct pcs_co_file *file)
{
	pcs_atomic32_store(&file->err_mask, 0);
	struct epoll_event ev = {.events = EPOLLET | POLLIN | POLLOUT | POLLRDHUP, .data = {.ptr = (void *)((ULONG_PTR)file | 1)}};
	if (epoll_ctl(pcs_current_proc->epollfd, EPOLL_CTL_ADD, file->fd, &ev)) {
		pcs_log_syserror(LOG_ERR, errno, "pcs_poll_file_init: epoll_ctl failed");
		BUG();
	}
}

void pcs_poll_file_fini(struct pcs_co_file *file)
{
}

void pcs_poll_file_begin(struct pcs_co_file *file, int mask)
{
}

#endif /* HAVE_EPOLL */
