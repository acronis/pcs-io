/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_RDMA_INT_H_
#define _PCS_RDMA_INT_H_ 1

#include <rdma/rdma_cma.h>

/* Internals shared among pcs_rdma_*.[ch] */

struct pcs_rdmaio *rio_create(struct pcs_process * proc, int hdr_size,
			      struct rdma_cm_id *cmid, int queue_depth);
void rio_ioconn_init(struct pcs_rdmaio *rio);
void rio_destroy(struct pcs_rdmaio *rio);

static inline void
conn_param_init(struct rdma_conn_param *cp, struct pcs_rdmaio_conn_req *cr)
{
	memset(cp, 0, sizeof(*cp));

	if (cr) {
		cp->private_data     = cr;
		cp->private_data_len = sizeof(*cr);
	}

	/* these two guys are about RDMA reads: see man rdma_connect(3) */
	cp->responder_resources = RDMA_MAX_RESP_RES;
	cp->initiator_depth     = RDMA_MAX_INIT_DEPTH;

	cp->flow_control        = 1; /* does not matter */
	cp->retry_count         = 5; /* # retransmissions when no ACK received */
	cp->rnr_retry_count     = 5; /* # RNR retransmissions */
}

/* From rdma-core/libibcm/cm.h */
enum ib_cm_rej_reason {
	IB_CM_REJ_INVALID_SERVICE_ID		= 8,
	IB_CM_REJ_CONSUMER_DEFINED		= 28,
};

/* From rdma/ib_verbs.h */
enum ib_qp_state {
	IB_QPS_RESET,
	IB_QPS_INIT,
	IB_QPS_RTR,
	IB_QPS_RTS,
	IB_QPS_SQD,
	IB_QPS_SQE,
	IB_QPS_ERR
};

static inline void pcs_log_errno(char *where, char *who)
{
	pcs_log(LOG_ERR, "%s(): %s failed: %s",
		where, who, strerror(errno));
}

static inline void pcs_log_event(char *where, int event, int status)
{
	char *s;

	switch (event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		s = "RDMA_CM_EVENT_CONNECT_REQUEST";
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		s = "RDMA_CM_EVENT_ESTABLISHED";
		break;
	case RDMA_CM_EVENT_REJECTED:
		s = "RDMA_CM_EVENT_REJECTED";
		break;
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		s = "RDMA_CM_EVENT_ADDR_RESOLVED";
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		s = "RDMA_CM_EVENT_ROUTE_RESOLVED";
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		s = "RDMA_CM_EVENT_DISCONNECTED";
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		s = "RDMA_CM_EVENT_DEVICE_REMOVAL";
		break;
	default:
		s = "UNKNOWN";
	}

	pcs_log(LOG_ERR, "%s(): RDMA event %s/%d with status %d",
		where, s, event, status);
}

#endif /* _PCS_RDMA_INT_H_ */
