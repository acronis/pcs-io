/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_poll.h"

#ifdef __SUN__

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
	if (conn->next_mask == 0)
		return port_dissociate(proc->port, PORT_SOURCE_FD, conn->fd);

	return port_associate(proc->port, PORT_SOURCE_FD, conn->fd, conn->next_mask, conn);
}


void pcs_poll_wait(struct pcs_evloop *evloop, int timeout)
{
	BUG_ON(evloop->nr_events);

	evloop->events[0].portev_user = NULL;

	struct timespec ts = {.tv_sec = timeout / 1000, .tv_nsec = (timeout % 1000) * 1000000};
	uint_t nr = 1;
	if (port_getn(evloop->proc->port, evloop->events, PCS_MAX_EVENTS_NR, &nr, &ts) >= 0 || errno == ETIME)
		evloop->nr_events = nr;
}

static void process_ioconn_event(port_event_t *ev)
{
	struct pcs_ioconn *conn = ev->portev_user;
	int events = ev->portev_events;

	switch (ev->portev_source) {
	case PORT_SOURCE_FD:
		conn->actual_mask = 0;

		if (likely(events & POLLIN))
			conn->data_ready(conn);

		if (unlikely(events & POLLOUT))
			conn->write_space(conn);

		if (unlikely(events & (POLLERR|POLLHUP|POLLNVAL)))
			conn->error_report(conn);

		pcs_ioconn_schedule(conn);
		break;

	case PORT_SOURCE_USER:
		conn->data_ready(conn);
		break;

	default:
		BUG();
	}
}

static void update_co_file_poll_mask(struct pcs_co_file *file, int mask_clear, int mask_set)
{
	pthread_mutex_lock(&file->mutex);
	file->mask = (file->mask & ~mask_clear) | mask_set;
	if (file->mask) {
		if (port_associate(pcs_current_proc->port, PORT_SOURCE_FD, file->fd, file->mask, (void *)((ULONG_PTR)file | 1))) {
			pcs_log_syserror(LOG_ERR, errno, "update_co_file_poll_mask: port_associate failed");
			BUG();
		}
	}
	pthread_mutex_unlock(&file->mutex);
}

static void process_co_file_event(port_event_t *ev)
{
	BUG_ON(ev->portev_source != PORT_SOURCE_FD);

	unsigned int events = ev->portev_events;
	if (events & (POLLERR|POLLHUP|POLLNVAL))
		events |= POLLIN|POLLOUT;

	struct pcs_co_file *file = (struct pcs_co_file *)((ULONG_PTR)ev->portev_user & ~(ULONG_PTR)1);
	update_co_file_poll_mask(file, events, 0);

	if (events & POLLIN)
		pcs_co_event_signal(&file->reader.ev);
	if (events & POLLOUT)
		pcs_co_event_signal(&file->writer.ev);
}

void pcs_poll_process_events(struct pcs_evloop *evloop)
{
	int i;
	for (i = 0; i < evloop->nr_events; i++) {
		port_event_t *ev = &evloop->events[i];

		if ((ULONG_PTR)ev->portev_user & 1)
			process_co_file_event(ev);
		else
			process_ioconn_event(ev);
	}

	evloop->nr_events = 0;
}

int pcs_poll_init(struct pcs_process *proc)
{
	proc->port = port_create();
	if (proc->port < 0)
		return -errno;
	return 0;
}

void pcs_poll_fini(struct pcs_process *proc)
{
	if (proc->port >= 0)
		close(proc->port);
	proc->port = -1;
}

void pcs_poll_file_init(struct pcs_co_file *file)
{
}

void pcs_poll_file_fini(struct pcs_co_file *file)
{
	update_co_file_poll_mask(file, ~0, 0);
}

void pcs_poll_file_begin(struct pcs_co_file *file, int mask)
{
	update_co_file_poll_mask(file, 0, mask);
}

#endif /* __SUN__ */
