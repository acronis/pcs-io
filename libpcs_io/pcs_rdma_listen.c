/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include <string.h>
#include <errno.h>

#include "pcs_types.h"
#include "log.h"
#include "pcs_rdma_listen.h"
#include "pcs_rdma_io.h"
#include "pcs_rdma_int.h"
#include "pcs_poll.h"
#include "pcs_malloc.h"

static struct pcs_netlisten_tops netlisten_tops;

static void rl_destroy(struct pcs_ioconn * conn)
{
	struct pcs_rdmalisten *rl = rdmalisten_from_ioconn(conn);

	if (rl->listen_cmid)
		rdma_destroy_id(rl->listen_cmid);

	pcs_free(conn);
}

static struct pcs_rdmalisten *
pcs_rdmalisten_alloc_sa(struct pcs_process * proc, struct sockaddr *sa, int len)
{
	struct pcs_rdmalisten *rl;

 	rl = pcs_malloc(sizeof(*rl) + len);
	if (!rl)
		return NULL;

	rl->listen_cmid = NULL;
	rl->sa_len = len;
	memcpy(rl->sa, sa, len);

	pcs_ioconn_init(proc, &rl->netlisten.ioconn);

	rl->netlisten.ioconn.destruct = rl_destroy;

	/* methods */
	rl->netlisten.tops = &netlisten_tops;

	return rl;
}

struct pcs_rdmalisten * pcs_rdmalisten_alloc(struct pcs_process * proc, const PCS_NET_ADDR_T *addr)
{
	struct pcs_rdmalisten *rl;
	struct sockaddr *sa = NULL;
	int len;

	if (pcs_netaddr2sockaddr(addr, &sa, &len))
		return NULL;

	rl = pcs_rdmalisten_alloc_sa(proc, sa, len);
	pcs_free(sa);
	return rl;
}

/* ioconn callbacks */

static int validate_conn_req(void *buf, int len, int *qd)
{
	struct pcs_rdmaio_conn_req *cr = buf;

	if (len < sizeof(*cr) ||
	    cr->magic != RIO_MAGIC ||
	    cr->version != RIO_VERSION ||
	    cr->msg_size != RIO_MSG_SIZE ||
	    cr->queue_depth > RIO_MAX_QUEUE_DEPTH)
		return EINVAL;

	*qd = cr->queue_depth;
	return 0;
}

static void rl_data_ready(struct pcs_ioconn * conn)
{
	struct pcs_rdmalisten *rl = rdmalisten_from_ioconn(conn);
	struct rdma_cm_event *ev;
	struct rdma_cm_id *cmid;
	enum rdma_cm_event_type event;
	int status;

	struct rdma_conn_param conn_param;
	struct pcs_rdmaio_rej  rej;

	struct rdma_event_channel *cm_chan;

	struct pcs_netlisten *nl = &rl->netlisten;
	struct pcs_process *proc = nl->cops->get_proc(nl);
	struct pcs_rdmaio *rio = NULL;
	int queue_depth;
	int err;
	void *private;

	if (rdma_get_cm_event(rl->listen_cmid->channel, &ev)) {
		pcs_log_errno("rl_data_ready", "rdma_get_cm_event");
		return;
	}

	event = ev->event;
	status = ev->status;
	cmid = ev->id;

	switch (event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		if (status) {
			pcs_log_event("rl_data_ready", event, status);
			break;
		}

		err = validate_conn_req((void *)ev->param.conn.private_data,
					ev->param.conn.private_data_len,
					&queue_depth);
		if (err) {
			rdma_ack_cm_event(ev);
			goto send_reject;
		}

		private = nl->cops->check_accept(nl);
		if (!private) {
			pcs_log_errno("rl_data_ready", "nl->cops->check_accept");
			err = ENOMEM;
			goto send_reject;
		}

		rio = rio_create(proc, nl->hdr_size, cmid, queue_depth);
		if (rio == NULL || rio->errored) {
			if (errno != EINVAL)
				pcs_log(LOG_ERR, "Was not able to pcs_rdmaio_fdinit()");
			err = ENOMEM;
			goto send_reject_accept;
		}
		cmid->context = rio;
		rio->private = private;

		conn_param_init(&conn_param, NULL);
		if (rdma_accept(cmid, &conn_param)) {
			pcs_log_errno("rl_data_ready", "rdma_accept");
			err = errno;
			goto send_reject_accept;
		}
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		rdma_ack_cm_event(ev);
		if (status) {
			pcs_log_event("rl_data_ready", event, status);
			goto disconnect;
		}

		cm_chan = rdma_create_event_channel();
		if (!cm_chan) {
			pcs_log_errno("rl_data_ready", "rdma_create_event_channel");
			err = errno;
			goto disconnect;
		}

		if (rdma_migrate_id(cmid, cm_chan)) {
			pcs_log_errno("rl_data_ready", "rdma_migrate_id");
			err = errno;
			rdma_destroy_event_channel(cm_chan);
			goto disconnect;
		}

		rio = cmid->context;
		rio_ioconn_init(rio);
		nl->cops->nl_accepted(nl, &rio->netio, rio->private);
		return;
	case RDMA_CM_EVENT_REJECTED:
		if (status != IB_CM_REJ_CONSUMER_DEFINED)
			pcs_log_event("rl_data_ready", event, status);
		rdma_ack_cm_event(ev);
		goto disconnect;
	default:
		pcs_log_event("rl_data_ready", event, status);
	}

	rdma_ack_cm_event(ev);
	return;

send_reject_accept:
	nl->cops->nl_accepted(nl, NULL, private);
send_reject:
	rej.cr.magic = RIO_MAGIC;
	rej.cr.version = RIO_VERSION;
	rej.cr.queue_depth = RIO_QUEUE_DEPTH;
	rej.cr.msg_size = RIO_MSG_SIZE;
	rej.error = err;

	if (rdma_reject(cmid, &rej, sizeof(rej)) && errno != EINVAL)
		pcs_log_errno("rl_data_ready", "rdma_reject");

	/*
	 * (rio && rio->errored) means rio destroy is already in progress.
	 * Useless and may be dangerous to call rio_destroy() again. And
	 * even more important we cannot rdma_destroy_id(cmid) now, because
	 * destroying will eventually call it via rio_free() */
	if (rio && !rio->errored)
		rio_destroy(rio);
	else if (rio == NULL) {
		pcs_log(LOG_ERR, ".0..... d cmid=%p ........", cmid);
		rdma_destroy_id(cmid);
	}
	return;

disconnect:
	rio = cmid->context;
	nl->cops->nl_accepted(nl, NULL, rio->private);
	rdma_disconnect(cmid);
	rio_destroy(rio);
}

/* netlisten transport operations */

static int rl_getmyname(struct pcs_netlisten *nl, PCS_NET_ADDR_T *addr)
{
	struct pcs_rdmalisten *rl = rdmalisten_from_netlisten(nl);
	struct sockaddr *sa;
	int err;

	if (!rl->listen_cmid)
		return -EINVAL;

	sa = rdma_get_local_addr(rl->listen_cmid);

	err  = pcs_sockaddr2netaddr(addr, sa);
	if (err)
		return err;

	addr->type = PCS_ADDRTYPE_RDMA;
	return 0;
}

static int rl_listen_start(struct pcs_netlisten *nl, int flags)
{
	struct pcs_rdmalisten *rl = rdmalisten_from_netlisten(nl);
	struct pcs_ioconn *conn = &nl->ioconn;

	struct rdma_event_channel *cm_chan;
	int err;

	cm_chan = rdma_create_event_channel();
	if (!cm_chan) {
		pcs_log_errno("rl_listen_start", "rdma_create_event_channel");
		return -errno;
	}

	if (rdma_create_id(cm_chan, &rl->listen_cmid, rl, RDMA_PS_TCP)) {
		pcs_log_errno("rl_listen_start", "rdma_create_id");
		err = errno;
		rdma_destroy_event_channel(cm_chan);
		return -err;
	}

	pcs_sock_nonblock(rl->listen_cmid->channel->fd);

	if (rdma_bind_addr(rl->listen_cmid, rl->sa)) {
		pcs_log_errno("rl_listen_start", "rdma_bind_addr");
		goto out_err;
	}

	if (rdma_listen(rl->listen_cmid, 16)) {
		pcs_log_errno("rl_data_ready", "rdma_listen");
		goto out_err;
	}

	conn->fd = rl->listen_cmid->channel->fd;
	conn->next_mask = POLLIN;
	conn->data_ready = rl_data_ready;
	pcs_ioconn_register(conn);

	return 0;

out_err:
	err = errno;
	rdma_destroy_id(rl->listen_cmid);
	return -err;
}

static struct pcs_netlisten_tops netlisten_tops = {
	.getmyname	= rl_getmyname,
	.listen_start	= rl_listen_start,
};
