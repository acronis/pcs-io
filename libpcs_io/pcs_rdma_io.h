/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_RDMA_IO_H_
#define _PCS_RDMA_IO_H_ 1

#include <rdma/rdma_cma.h>

#include "pcs_types.h"
#include "pcs_sock.h"
#include "pcs_process.h"
#include "pcs_error.h"
#include "log.h"
#include "pcs_net.h"
#include "pcs_rdma_prot.h"

/* We don't send NOOP until save up RIO_QUEUE_DEPTH/2 outstanding credits,
   hence we don't expect more than two NOOP in-flight */
#define RIO_NOOP_CREDITS 2

/* per connection */
#define RIO_N_RXS (RIO_QUEUE_DEPTH * 2 + 2)
#define RIO_N_TXS (RIO_QUEUE_DEPTH + 2)
/* NB: change RIO_N_RXS to (RIO_QUEUE_DEPTH * 2 + 2) as soon as we start sending ACK-s */

/* per rdma device */
#define RIO_N_TXS_PER_DEV 2000

enum {
	RIO_STATE_CONNECTING,   /* needn't rdma_disconnect (yet) */
	RIO_STATE_ESTABLISHED,  /* main "working" state */
	RIO_STATE_DISCONNECTED, /* needn't rdma_disconnect (already) */
	RIO_STATE_ABORTED,      /* rio_abort was called at least once */
};

struct pcs_rdmaio
{
	/*
	 * That's not very obvious, we need two poll-able objects: netio.iocomp
	 * and compc. The former handles DISCONNECT event. The latter (compc)
	 * handles WQE completion events. */
	struct pcs_netio  netio;
	struct pcs_ioconn compc;
	int refcnt;

	int rio_state; /* see enum above */

	/*
	 * Intentionally switch rdma-engine to errored state forcing
	 * completion of all posted RXs and TXs. Being in this state, we only
	 * have to count total number of posted RXs and TXs, and, when it
	 * drops to zero, schedule freeing rio. See rio_destroy() and
	 * rio_handle_errored() for details */
	int errored;

	int hdr_size;  /* minimum allowed payload */

	/*
	 * It's easier to have the same queue_depth for both directions.
	 * rdma_connect gets a value from a tunable and sends it via
	 * conn_param; rdma_listen sees it in conn request event and
	 * blindly accepts the value. */
	int queue_depth;


	struct rio_rx *rx_descs; /* plain array of RX descriptors */
	char          *rx_bufs;  /* MR-ed area for payload of RXs */
	struct ibv_mr *rx_mr;      /* covers rx_bufs */
	struct cd_list pended_rxs; /* list head of pended RX frames */

	int n_rx_posted; /* # posted RXs */
	int n_tx_posted; /* # posted TXs */

	int n_peer_credits; /* what we think about peer's n_rx_posted */
	int n_reserved_credits; /* limits # RDMA in flight */

	int n_os_credits;   /* outstanding credits: # RXs we re-post-ed,
			     * but have not returned to our peer (yet) */

	int n_th_credits;   /* threshold: when to return outstanding
			     * credits urgently */

	struct pcs_process *proc; /* need for sio_count ++/-- */
	void *private; /* stash ep between check_accept and nl_accepted */

	struct pcs_rdma_device  *dev;
	struct rdma_cm_id	*cmid;
	struct ibv_comp_channel	*cc;
	struct ibv_cq		*cq;

	struct cd_list           write_queue;
	int	                 write_queue_len; /* # messages */

	struct cd_list           reserved_queue; /* out of reserved credits */
	int	                 reserved_queue_len; /* # messages */

	int no_kick;   /* do not kick processing write_queue */
	int throttled; /* pcs_rpc asked us to quiesce */

	struct cd_list active_txs; /* list head of active TX frames: tx->msg->done()
				    * is postponed until ACK from our peer */

	u64 xid_generator; /* provides unique (per rio) xids */

	struct pcs_rdmaio_conn_req conn_req;
};

struct pcs_rdmaio_stats {
	u64 memory_regs_total; /* total amount of ibv_reg_mr_calls */
	u64 memory_deregs_total; /* total amout of ibv_dereg_mr calls */
	ssize_t memory_registered; /* the amout of registered memory */
	u64 bounce_buf_total; /* total amout of data transfered via bb */
};
extern struct pcs_rdmaio_stats pcs_rdmaio_stats;

#define rio_from_netio(nio) container_of(nio, struct pcs_rdmaio, netio)
#define rio_from_ioconn(conn) container_of(conn, struct pcs_rdmaio, netio.ioconn)
#define rio_from_compc(conn) container_of(conn, struct pcs_rdmaio, compc)

#endif /* _PCS_RDMA_IO_H_ */
