/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_types.h"
#include "pcs_sock_conn.h"
#include "pcs_sock_io.h"
#include "pcs_errno.h"
#include "pcs_poll.h"
#include "pcs_malloc.h"
#include "log.h"

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <memory.h>
#include <stdlib.h>

#define sockconnect_from_ioconn(conn) container_of(conn, struct pcs_sockconnect, netconn.ioconn)

static struct pcs_netconnect_tops netconn_tops;

/* Socket connect work. Just do asynchronous connect, nothing else */
static void sockconn_write_space(struct pcs_ioconn * conn)
{
	struct pcs_sockconnect * sh = sockconnect_from_ioconn(conn);
	if (connect(conn->fd, sh->sa, sh->sa_len)) {
		int err = pcs_sock_errno();
		if (err == EALREADY)
			return;

		/* EISCONN == successfully connected */
		if (err != EISCONN) {
			sh->error = err ? err : EIO;
			TRACE("Connect failed, errno=%d", err);
		}
	}
	sh->complete(sh);
}

static void sockconn_error_report(struct pcs_ioconn * conn)
{
	struct pcs_sockconnect * sh = sockconnect_from_ioconn(conn);
	int error;

	socklen_t so_len = sizeof(error);
	if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, (char*)&error, &so_len))
		error = EINVAL;

	TRACE("Connect failed, errno=%d", error);

	sh->error = error;
	sh->complete(sh);
}

void pcs_sockconnect_abort(struct pcs_sockconnect * conn, int error)
{
	conn->error = error;
	conn->complete(conn);
}

void pcs_sockconnect_destroy(struct pcs_ioconn * conn)
{
	conn->proc->conn_count--;
	pcs_ioconn_destruct(conn);
}

struct pcs_sockconnect *
pcs_sockconnect_init(struct pcs_process * proc, PCS_NET_ADDR_T * addr)
{
	struct pcs_sockconnect *sh;
	struct sockaddr *sa = NULL;
	int len;

	if (pcs_netaddr2sockaddr(addr, &sa, &len))
		return NULL;

	sh = pcs_sockconnect_init_sa(proc, sa, len);
	pcs_free(sa);
	return sh;
}

static void sc_complete(struct pcs_sockconnect *sh)
{
	struct pcs_netconnect *nc = &sh->netconn;
	struct pcs_process *proc = nc->cops->get_proc(nc);
	struct pcs_sockio * sio;

	if (nc->cops->handle_errors(nc, sh->error))
		return;

	sio = pcs_sockio_fdinit(proc, nc->ioconn.fd,
				nc->alloc_size, nc->hdr_size);

	if (sio == NULL) {
		nc->cops->sched_reconnect(nc, PCS_ERR_NET);
		return;
	}

	nc->cops->nc_complete(nc, &sio->netio);
}

struct pcs_sockconnect *
pcs_sockconnect_init_sa(struct pcs_process * proc, struct sockaddr *sa, int len)
{
	struct pcs_sockconnect *sh;

	sh = pcs_malloc(sizeof(struct pcs_sockconnect) + len);
	if (!sh)
		return NULL;

	proc->conn_count++;

	sh->error = 0;
	sh->sa_len = len;
	memcpy(&sh->sa, sa, len);

	pcs_ioconn_init(proc, &sh->netconn.ioconn);

	sh->netconn.ioconn.destruct = pcs_sockconnect_destroy;

	/* methods */
	sh->netconn.tops = &netconn_tops;

	/* callbacks: those who use sh directly (bypassing pcs_rpc) will override */
	sh->complete = sc_complete;

	return sh;
}

void pcs_sockconnect_start(struct pcs_process * proc, struct pcs_sockconnect * sh)
{
	int fd;
	int err;

	while (1) {
		fd = socket(sh->sa->sa_family, SOCK_STREAM, 0);
		if (!pcs_sock_invalid(fd))
			break;

		err = pcs_sock_errno();
		if (err == EMFILE || err == ENFILE) {
			if (pcs_fd_gc(proc))
				continue;
		}
		goto done;
	}

	pcs_sock_nonblock(fd);

	err = connect(fd, sh->sa, sh->sa_len);
	if (err)
		err = pcs_sock_errno();

	if (err == 0 || err == EINPROGRESS)
	{
		struct pcs_ioconn *conn = &sh->netconn.ioconn;
		conn->fd = fd;
		conn->next_mask = POLLOUT;
		conn->write_space = sockconn_write_space;
		conn->error_report = sockconn_error_report;
		pcs_ioconn_register(conn);
		return;
	}

	pcs_sock_close(fd);
done:
	sh->error = err ? err : EIO;
	sh->complete(sh);
}

static void sc_abort_connect(struct pcs_netconnect * conn, int error)
{
	pcs_sockconnect_abort(sockconn_from_netconn(conn), error);
}

/* netconnect transport operations */

static int sc_getmyname(struct pcs_netconnect *netconn, PCS_NET_ADDR_T * addr)
{
	return pcs_sock_getsockname(netconn->ioconn.fd, addr);
}

static void sc_connect_start(struct pcs_netconnect *nc)
{
	struct pcs_process *proc = nc->cops->get_proc(nc);
	struct pcs_sockconnect *sh = sockconn_from_netconn(nc);

	pcs_sockconnect_start(proc, sh);
}

static struct pcs_netconnect_tops netconn_tops = {
	.abort_connect	= sc_abort_connect,
	.getmyname	= sc_getmyname,
	.connect_start	= sc_connect_start,
};
