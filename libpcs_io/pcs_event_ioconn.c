/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_types.h"
#include "pcs_event_ioconn.h"
#include "pcs_poll.h"
#include "pcs_malloc.h"
#include "bug.h"

#if !defined(__WINDOWS__)

#include "pcs_eventfd.h"

#include <errno.h>
#include <unistd.h>

static void event_data_ready(struct pcs_ioconn *conn)
{
	struct pcs_event_ioconn *event = container_of(conn, struct pcs_event_ioconn, ioconn);

#if defined(HAVE_EVENTFD)
	u64 efd_buf;
	int res = read(conn->fd, &efd_buf, 8);
	(void)res;
#elif defined(HAVE_KQUEUE)
	/* nothing to do */
#elif defined(__SUN__)
	/* nothing to do */
#else /* pipe */
	char buf[128];
	while (read(conn->fd, buf, sizeof(buf)) == sizeof(buf))
		/* */;
#endif

	event->data_ready(event->priv);
}

int pcs_event_ioconn_init(struct pcs_process *proc, struct pcs_event_ioconn **event_p, void (*data_ready)(void *priv), void *priv)
{
	struct pcs_event_ioconn *event = pcs_xmalloc(sizeof(*event));
	event->data_ready = data_ready;
	event->priv = priv;
	event->send_event_fd = -1;

	struct pcs_ioconn * conn = &event->ioconn;
	pcs_ioconn_init(proc, conn);
	conn->next_mask = POLLIN | EPOLLET;
	conn->data_ready = event_data_ready;

#if defined(HAVE_EVENTFD)
	int fd = eventfd(0, 0);
	if (fd < 0) {
		int err = -errno;
		pcs_free(event);
		return err;
	}

	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
	conn->fd = event->send_event_fd = fd;
	pcs_ioconn_register(conn);
#elif defined(HAVE_KQUEUE)
	struct kevent ev = {.ident = (uintptr_t)event, .filter = EVFILT_USER, .flags = EV_ADD | EV_CLEAR, .udata = &event->ioconn};
	if (kevent(proc->kqueue, &ev, 1, NULL, 0, NULL)) {
		int err = -errno;
		pcs_free(event);
		return err;
	}
#elif defined(__SUN__)
	/* nothing to do */
#else /* pipe */
	int fds[2];
	if (pipe(fds) < 0) {
		int err = -errno;
		pcs_free(event);
		return err;
	}

	fcntl(fds[0], F_SETFL, fcntl(fds[0], F_GETFL, 0) | O_NONBLOCK);
	fcntl(fds[1], F_SETFL, fcntl(fds[1], F_GETFL, 0) | O_NONBLOCK);
	conn->fd = fds[0];
	event->send_event_fd = fds[1];
	pcs_ioconn_register(conn);
#endif

	*event_p = event;
	return 0;
}

void pcs_event_ioconn_wakeup(struct pcs_event_ioconn *event)
{
#if defined(HAVE_EVENTFD)
	u64 ev = 1;
	int res = write(event->send_event_fd, &ev, 8);
	BUG_ON(res < 0 && errno != EAGAIN);
#elif defined(HAVE_KQUEUE)
	struct kevent ev = {.ident = (uintptr_t)event, .filter = EVFILT_USER, .fflags = NOTE_TRIGGER, .udata = &event->ioconn};
	int res = kevent(event->ioconn.proc->kqueue, &ev, 1, NULL, 0, NULL);
	BUG_ON(res < 0);
#elif defined(__SUN__)
	int res = port_send(event->ioconn.proc->port, 0, &event->ioconn);
	BUG_ON(res < 0);
#else /* pipe */
	unsigned char ev = 0;
	/* write() can fail with EAGAIN. We do not care, pipe is not empty, it is enough */
	int res = write(event->send_event_fd, &ev, 1);
	BUG_ON(res < 0 && errno != EAGAIN);
#endif
}

void pcs_event_ioconn_close(struct pcs_event_ioconn *event)
{
#if defined(HAVE_EVENTFD)
	pcs_ioconn_unregister(&event->ioconn);
#elif defined(HAVE_KQUEUE)
	struct kevent ev = {.ident = (uintptr_t)event, .filter = EVFILT_USER, .flags = EV_DELETE, .udata = &event->ioconn};
	kevent(event->ioconn.proc->kqueue, &ev, 1, NULL, 0, NULL);
	pcs_free(event);
#elif defined(__SUN__)
	pcs_free(event);
#else /* pipe */
	/* close one end of pipe, another end will be closed by ioconn destructor */
	if (event->send_event_fd >= 0) {
		close(event->send_event_fd);
		event->send_event_fd = -1;
	}
	pcs_ioconn_unregister(&event->ioconn);
#endif
}

#else /* __WINDOWS__ */

static void event_data_ready(struct pcs_iocp *iocp)
{
	struct pcs_event_ioconn *event = container_of(iocp, struct pcs_event_ioconn, iocp);
	event->data_ready(event->priv);
}

int pcs_event_ioconn_init(struct pcs_process *proc, struct pcs_event_ioconn **event_p, void (*data_ready)(void *priv), void *priv)
{
	struct pcs_event_ioconn *event = pcs_xmalloc(sizeof(*event));
	event->proc = proc;
	event->data_ready = data_ready;
	event->priv = priv;
	event->iocp.done = event_data_ready;
	memset(&event->iocp.overlapped, 0, sizeof(event->iocp.overlapped));
	*event_p = event;
	return 0;
}

void pcs_event_ioconn_wakeup(struct pcs_event_ioconn *event)
{
	pcs_iocp_send(event->proc, &event->iocp);
}

void pcs_event_ioconn_close(struct pcs_event_ioconn *event)
{
	pcs_free(event);
}

#endif /* __WINDOWS__ */
