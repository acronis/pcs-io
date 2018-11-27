/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include <string.h>
#include <errno.h>

#include "pcs_types.h"
#include "pcs_rdma_conn.h"
#include "pcs_rdma_io.h"
#include "pcs_rdma_int.h"
#include "pcs_poll.h"
#include "pcs_malloc.h"
#include "log.h"

#define RESOLVE_TIMEOUT_MS 5000

static struct pcs_netconnect_tops netconn_tops;

static void rc_destroy(struct pcs_ioconn * conn)
{
	struct pcs_rdmaconnect *rc = rdmaconn_from_ioconn(conn);
	struct rdma_event_channel *cmc;

	if (rc->rio)
		rio_destroy(rc->rio);
	else if (rc->cmid) {
		cmc = rc->cmid->channel;
		rdma_destroy_id(rc->cmid);
		rdma_destroy_event_channel(cmc);
	}

	conn->proc->conn_count--;
	pcs_free(conn);
}

static struct pcs_rdmaconnect *
pcs_rdmaconnect_init_sa(struct pcs_process * proc, struct sockaddr *sa, int len)
{
	struct pcs_rdmaconnect *rc;

	rc = pcs_xzmalloc(sizeof(*rc) + len);

	proc->conn_count++;

	rc->cmid = NULL;
	rc->sa_len = len;
	memcpy(&rc->sa, sa, len);

	pcs_ioconn_init(proc, &rc->netconn.ioconn);

	rc->netconn.ioconn.destruct = rc_destroy;

	/* methods */
	rc->netconn.tops = &netconn_tops;

	return rc;
}

struct pcs_rdmaconnect *
pcs_rdmaconnect_init(struct pcs_process * proc, PCS_NET_ADDR_T * addr)
{
	struct pcs_rdmaconnect *rc;
	struct sockaddr *sa = NULL;
	int len;

	if (pcs_netaddr2sockaddr(addr, &sa, &len))
		return NULL;

	rc = pcs_rdmaconnect_init_sa(proc, sa, len);
	pcs_free(sa);
	return rc;
}

/* ioconn callbacks */

static void rc_data_ready(struct pcs_ioconn * conn)
{
	struct pcs_rdmaconnect *rc   = rdmaconn_from_ioconn(conn);
	struct pcs_netconnect  *nc   = &rc->netconn;
	struct pcs_process     *proc = nc->cops->get_proc(nc);
	struct rdma_cm_id      *cmid = rc->cmid ? : rc->rio->cmid;
	struct rdma_cm_event   *ev;
	struct pcs_rdmaio      *rio;
	struct rdma_conn_param  conn_param;
	enum rdma_cm_event_type event;
	int status, len;

	if (rdma_get_cm_event(cmid->channel, &ev)) {
		pcs_log_errno("rc_data_ready", "rdma_get_cm_event");
		goto connect_failed_early;
	}

	event = ev->event;
	status = ev->status;

	switch (event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		if (status) {
			pcs_log_event("rc_data_ready", event, status);
			goto connect_failed;
		}

		if (rdma_resolve_route(cmid, RESOLVE_TIMEOUT_MS)) {
			pcs_log_errno("rc_data_ready", "rdma_resolve_route");
			goto connect_failed;
		}
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		if (status) {
			pcs_log_event("rc_data_ready", event, status);
			goto connect_failed;
		}

		rc->rio = rio_create(proc, nc->hdr_size, cmid, RIO_QUEUE_DEPTH);
		if (rc->rio == NULL)
			goto connect_failed;

		rc->cmid = NULL; /* rc->rio owns the cmid */

		if (rc->rio->errored) {
			rc->rio = NULL; /* rio_create scheduled rio destroy */
			goto connect_failed;
		}

		conn_param_init(&conn_param, &rc->rio->conn_req);
		if (rdma_connect(cmid, &conn_param)) {
			pcs_log_errno("rc_data_ready", "rdma_connect");
			goto connect_failed;
		}
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		BUG_ON(!rc->rio);
		if (status) {
			pcs_log_event("rc_data_ready", event, status);
			goto connect_failed;
		}

		/* detach rio from rc; otherwise rc_destroy() will kill it */
		rio = rc->rio;
		rc->rio = NULL;

		rio_ioconn_init(rio);
		nc->cops->handle_errors(nc, 0);
		nc->cops->nc_complete(nc, &rio->netio);
		break;
	case RDMA_CM_EVENT_REJECTED:
		switch (status) {
		case IB_CM_REJ_INVALID_SERVICE_ID: /* peer doesn't listen */
			break;
		case IB_CM_REJ_CONSUMER_DEFINED:
			len = ev->param.conn.private_data_len;
			if (len < sizeof(struct pcs_rdmaio_rej))
				pcs_log(LOG_ERR, "RDMA REJECT: len=%d", len);
			else {
				struct pcs_rdmaio_rej *rej = (void *)ev->param.conn.private_data;
				pcs_log(LOG_ERR, "RDMA REJECT: reason=%d", rej->error);
			}
			break;
		default:
			pcs_log_event("rc_data_ready", event, status);
		}
		nc->cops->handle_errors(nc, PCS_ERR_NET);
		break;
	default:
		pcs_log_event("rc_data_ready", event, status);
		goto connect_failed;
	}
	rdma_ack_cm_event(ev);
	return;

connect_failed:
	rdma_ack_cm_event(ev);
connect_failed_early:
	nc->cops->handle_errors(nc, PCS_ERR_NET);
}

/* netconnect transport operations */

static void rc_abort_connect(struct pcs_netconnect *nc, int error)
{
	nc->cops->handle_errors(nc, error);
}

static int rc_getmyname(struct pcs_netconnect *nc, PCS_NET_ADDR_T * addr)
{
	struct pcs_rdmaconnect *rc = rdmaconn_from_netconn(nc);
	struct sockaddr *sa;
	int err;

	if (!rc->cmid)
		return -EINVAL;

	sa = rdma_get_local_addr(rc->cmid);

	err  = pcs_sockaddr2netaddr(addr, sa);
	if (err)
		return err;

	addr->type = PCS_ADDRTYPE_RDMA;
	return 0;
}

static void rc_connect_start(struct pcs_netconnect *nc)
{
	struct pcs_process *proc = nc->cops->get_proc(nc);
	struct pcs_rdmaconnect *rc = rdmaconn_from_netconn(nc);
	struct pcs_ioconn *conn = &nc->ioconn;

	struct rdma_event_channel *cm_chan;

	for (;;) {
		cm_chan = rdma_create_event_channel();
		if (cm_chan)
			break;

		pcs_log_errno("rc_connect_start", "rdma_create_event_channel");

		if (errno == EMFILE || errno == ENFILE) {
			if (pcs_fd_gc(proc))
				continue;
		}
		goto out_err;
	}

	if (rdma_create_id(cm_chan, &rc->cmid, NULL, RDMA_PS_TCP)) {
		pcs_log_errno("rc_connect_start", "rdma_create_id");
		goto out_err2;
	}

	pcs_sock_nonblock(rc->cmid->channel->fd);

	if (rdma_resolve_addr(rc->cmid, NULL, rc->sa, RESOLVE_TIMEOUT_MS)) {
		pcs_log_errno("rc_connect_start", "rdma_resolve_addr");
		goto out_err2;
	}

	conn->fd = rc->cmid->channel->fd;
	conn->next_mask = POLLIN;
	conn->data_ready = rc_data_ready;
	pcs_ioconn_register(conn);

	return;

out_err2:
	if (rc->cmid)
		rdma_destroy_id(rc->cmid);
	rdma_destroy_event_channel(cm_chan);
out_err:
	nc->cops->handle_errors(nc, PCS_ERR_NET);
}

static struct pcs_netconnect_tops netconn_tops = {
	.abort_connect	= rc_abort_connect,
	.getmyname	= rc_getmyname,
	.connect_start	= rc_connect_start,
};
