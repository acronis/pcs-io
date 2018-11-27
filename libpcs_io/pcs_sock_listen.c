/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_types.h"

#include <errno.h>
#include <memory.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>

#include <stdlib.h>

#include "pcs_sock_listen.h"
#include "pcs_sock_io.h"
#include "pcs_poll.h"
#include "pcs_ioconn.h"
#include "pcs_malloc.h"
#include "log.h"

#define socklisten_from_ioconn(conn) container_of(conn, struct pcs_socklisten, netlisten.ioconn)

static struct pcs_netlisten_tops netlisten_tops;

static void data_ready(struct pcs_ioconn * conn)
{
	struct pcs_socklisten * sh = socklisten_from_ioconn(conn);

	for (;;) {
		pcs_sock_t fd;

		fd = accept(conn->fd, NULL, NULL);
		if (pcs_sock_invalid(fd)) {
			int sock_err = errno;
			int gc_progress = pcs_fd_gc_on_error(conn->proc, sock_err, PCS_GC_FD_ON_ACCEPT);
			if (gc_progress < 0)
				return;

			pcs_log(LOG_ERR, "connection lost because of EM/NFILE %d", sock_err);
			if (gc_progress == 0) {
				conn->next_mask &= ~POLLIN;
				mod_timer(&sh->throttle_timer, PCS_SOCKLISTEN_THROTTLE_DELAY);
			}
			return;
		}

		sh->accepted(sh, fd);
	}
}

static void pcs_socklisten_destroy(struct pcs_ioconn * conn)
{
	struct pcs_socklisten * sh = socklisten_from_ioconn(conn);

	del_timer_sync(&sh->throttle_timer);
	pcs_ioconn_destruct(conn);
}

static void throttle_timeout(void * data)
{
	struct pcs_socklisten * sh = data;
	struct pcs_ioconn *conn = &sh->netlisten.ioconn;

	conn->next_mask |= POLLIN;
	pcs_ioconn_schedule(conn);
}

struct pcs_socklisten * pcs_socklisten_alloc(struct pcs_process * proc, const PCS_NET_ADDR_T *addr)
{
	struct pcs_socklisten *sh;
	struct sockaddr *sa = NULL;
	int len;

	if (pcs_netaddr2sockaddr(addr, &sa, &len))
		return NULL;

	sh = pcs_socklisten_alloc_sa(proc, sa, len);
	pcs_free(sa);
	return sh;
}

static void sl_accepted(struct pcs_socklisten *sl, pcs_sock_t fd)
{
	struct pcs_netlisten *nl = &sl->netlisten;
	struct pcs_process *proc = nl->cops->get_proc(nl);
	struct pcs_sockio * sio;
	void *private;

	private = nl->cops->check_accept(nl);
	if (!private) {
		pcs_sock_close(fd);
		return;
	}
	
	sio = pcs_sockio_fdinit(proc, fd, nl->alloc_size, nl->hdr_size);
	if (!sio) {
		pcs_sock_close(fd);
		pcs_log(LOG_ERR, "Was not able to pcs_sockio_fdinit()");
	}

	nl->cops->nl_accepted(nl, sio ? &sio->netio : NULL, private);
}

struct pcs_socklisten * pcs_socklisten_alloc_sa(struct pcs_process * proc, struct sockaddr *sa, int len)
{
	struct pcs_socklisten *sl;
	int sl_len = sizeof(*sl) + len;

 	sl = pcs_malloc(sl_len);
	if (!sl)
		return NULL;

	pcs_ioconn_init(proc, &sl->netlisten.ioconn);

	init_timer(proc, &sl->throttle_timer, throttle_timeout, sl);

	sl->sa_len = len;
	memcpy(sl->sa, sa, len);
	sl->netlisten.ioconn.destruct = pcs_socklisten_destroy;

	/* methods */
	sl->netlisten.tops = &netlisten_tops;

	/* callbacks: those who use sl directly (bypassing pcs_rpc) will override */
	sl->accepted = sl_accepted;

	return sl;
}

int pcs_socklisten_start(struct pcs_process * proc, struct pcs_socklisten * sh, int flags)
{
	int val, err;
	pcs_sock_t fd;
	struct pcs_ioconn *conn = &sh->netlisten.ioconn;

	fd = socket(sh->sa->sa_family, SOCK_STREAM, 0);
	if (pcs_sock_invalid(fd))
		return -pcs_sock_errno();

	pcs_sock_nonblock(fd);

	val = 1;
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&val, sizeof(val));

	if (bind(fd, sh->sa, sh->sa_len)) {
#ifdef __linux__
#ifndef IP_FREEBIND	/* just in case old glibc is used */
#define IP_FREEBIND	15
#endif
		if ((errno != EADDRNOTAVAIL) || ((flags & PCS_SK_FREEBIND) == 0))
			goto out_err;
		pcs_log(LOG_WARN, "bind() failed: %s; retrying with IP_FREEBIND",
				strerror(errno));
		(void)setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &val, sizeof(val));
		if (bind(fd, sh->sa, sh->sa_len))
#endif /* __linux__ */
			goto out_err;
	}

	if (listen(fd, 16))
		goto out_err;

	conn->fd = fd;
	conn->next_mask = POLLIN;
	conn->data_ready = data_ready;
	pcs_ioconn_register(conn);

	return 0;

out_err:
	err = pcs_sock_errno();
	pcs_sock_close(fd);
	return -err;
}

static void dont_accept(struct pcs_socklisten * sh, pcs_sock_t fd)
{
	pcs_sock_close(fd);
}

void pcs_socklisten_stop(struct pcs_socklisten * sh)
{
	sh->accepted = &dont_accept;
	pcs_ioconn_unregister(&sh->netlisten.ioconn);
}

/* netlisten transport operations */

static int sl_getmyname(struct pcs_netlisten *nl, PCS_NET_ADDR_T * addr)
{
	return pcs_sock_getsockname(nl->ioconn.fd, addr);
}

int sl_listen_start(struct pcs_netlisten *nl, int flags)
{
	struct pcs_process *proc = nl->cops->get_proc(nl);
	struct pcs_socklisten *sl = socklisten_from_netlisten(nl);

	return pcs_socklisten_start(proc, sl, flags);
}

static struct pcs_netlisten_tops netlisten_tops = {
	.getmyname	= sl_getmyname,
	.listen_start	= sl_listen_start,
};
