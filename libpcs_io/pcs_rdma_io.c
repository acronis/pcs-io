/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include <string.h>
#include <errno.h>

#include "pcs_types.h"
#include "pcs_sock_io.h"
#include "pcs_rdma_io.h"
#include "pcs_rdma_int.h"
#include "pcs_poll.h"
#include "pcs_malloc.h"
#include "pcs_mr_malloc.h"
#include "log.h"

#include <rdma/rdma_verbs.h>

struct rio_rx {
	struct cd_list  list;
};

enum {
	TX_FREE,                   /* free tx request available for use */
	TX_WAIT_FOR_TX_COMPL,      /* tx request sent, wait for TX completion */
	TX_WAIT_FOR_READ_ACK,      /* wait for peer to ack RDMA read */
	TX_MSG_DONE,               /* default: call msg->done() */
	TX_SUBMIT_RDMA_READ_ACK,   /* let our peer know that our RDMA_READ is done */
};
BUILD_BUG_ON((TX_WAIT_FOR_READ_ACK - TX_WAIT_FOR_TX_COMPL) != 1);
BUILD_BUG_ON((TX_MSG_DONE - TX_WAIT_FOR_READ_ACK) != 1);

struct rio_tx {
	struct cd_list  list;      /* either member of rio->dev->free_txs or rio->active_txs */
	struct pcs_msg *msg;       /* msg to call ->done() when we're done */
	struct ibv_mr  *mr;        /* optional, map-on-demand, rare case */
	void           *bbuf;      /* bounce buffer to transfer data spread between two or more memory regions */
	u64             xid;       /* xid that we've read from wire; used to construct ACK */
	int             tx_state;  /* what we should do on TX completion; see enum above */
};

struct pcs_rdma_device {
	struct cd_list      list;
	struct ibv_context *verbs;
	struct ibv_pd      *pd;

	struct rio_tx *tx_descs; /* plain array of TX descriptors */
	char          *tx_bufs;  /* MR-ed area for payload of TXs */
	struct ibv_mr *tx_mr;    /* covers tx_bufs */
	struct cd_list free_txs; /* list head of free TX frames */
};
CD_LIST_HEAD(pcs_rdma_devices);

struct pcs_netio_tops netio_tops;

/*
 * Here is a trick: we pack the addr of a TX/RX along with its type into
 * uint64_t wr_id. Afterwards, when we get it back in completion, we
 * can easily discern who (RX or TX) was completed.
 */
enum {
	RIO_UNDEFINED_COMPL,
	RIO_RX_COMPL,
	RIO_TX_COMPL,
};

struct pcs_rdmaio_stats pcs_rdmaio_stats;

#define RIO_WR_ID_MASK 0x3

static void *rio_wr_id_split(ULONG_PTR wr_id, int *type)
{
	*type = wr_id & RIO_WR_ID_MASK;
	return (void *)(wr_id & ~RIO_WR_ID_MASK);
}

static void *rio_wr_id_build(void *ctx, int type)
{
	ULONG_PTR wr_id = (ULONG_PTR)ctx;
	BUG_ON(wr_id & RIO_WR_ID_MASK);
	BUG_ON(type & ~RIO_WR_ID_MASK);
	return (void *)(wr_id | type);
}

/*
 * A trivial helper representing 1:1 mapping between
 * rio->rx_descs[RIO_N_RX] and rio->rx_bufs[RIO_N_RXS * RIO_MSG_SIZE]
 */
static char *rx2buf(struct pcs_rdmaio *rio, struct rio_rx *rx)
{
	return rio->rx_bufs + RIO_MSG_SIZE * (rx - rio->rx_descs);
}

/* Only called when rio->write_queue is not empty */
static struct pcs_msg *rio_dequeue_msg(struct pcs_rdmaio *rio)
{
	struct pcs_msg *msg = cd_list_first_entry(&rio->write_queue,
						  struct pcs_msg, list);
	cd_list_del(&msg->list);
	rio->write_queue_len--;
	return msg;
}

/* Only called when rio->reserved_queue is not empty */
static struct pcs_msg *rio_dequeue_reserved_msg(struct pcs_rdmaio *rio)
{
	struct pcs_msg *msg = cd_list_first_entry(&rio->reserved_queue,
						  struct pcs_msg, list);
	cd_list_del(&msg->list);
	rio->reserved_queue_len--;
	return msg;
}

static void rio_msg_sent(struct pcs_rdmaio *rio, struct rio_tx *tx, struct pcs_msg *msg, int done)
{
	if (done) {
		rio->no_kick = 1;
		pcs_msg_sent(msg);
		msg->done(msg);
		rio->no_kick = 0;
	} else {
		tx->msg = msg;
		cd_list_add_tail(&tx->list, &rio->active_txs);
	}
}

static void rio_mr_free(void *mr_ctx, void *pd_ctx)
{
	struct ibv_mr *mr = mr_ctx;

	BUG_ON(mr == NULL);
	ibv_dereg_mr(mr);

	pcs_rdmaio_stats.memory_deregs_total++;
	pcs_rdmaio_stats.memory_registered -= mr->length;
	BUG_ON(pcs_rdmaio_stats.memory_registered < 0);
}

static int rio_mr_alloc(struct pcs_rdmaio *rio, void *addr, int len, struct ibv_mr **mr)
{
	if (len == -PCS_MR_POOL_BUF) {
		struct pcs_mr_buf *buf = addr;
		void *bbuf;
		size_t bbuf_len;

		BUG_ON(buf->ctx == NULL);
		BUG_ON(buf->ctx->mr_ctx && buf->ctx->pd_ctx != rio->dev->pd);
		if (buf->ctx->mr_ctx != NULL) {
			*mr = buf->ctx->mr_ctx;
			return 0;
		}

		BUG_ON(buf->ctx->pd_ctx);
		bbuf = pcs_mrc2buf(buf->ctx, &bbuf_len);

		*mr = ibv_reg_mr(rio->dev->pd, bbuf, bbuf_len,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_WRITE);
		BUG_ON(*mr == NULL);

		pcs_rdmaio_stats.memory_regs_total++;
		pcs_rdmaio_stats.memory_registered += bbuf_len;

		buf->ctx->mr_ctx = *mr;
		buf->ctx->pd_ctx = rio->dev->pd;
		buf->ctx->mr_free_cb = rio_mr_free;

		return 0;
	} else if (len > 0) {
		*mr = ibv_reg_mr(rio->dev->pd, addr, len,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_WRITE);
		BUG_ON(*mr == NULL);

		pcs_rdmaio_stats.memory_regs_total++;
		pcs_rdmaio_stats.memory_registered += len;

		return 1;
	}

	BUG();
}

static struct rio_tx *rio_get_tx(struct pcs_rdma_device *dev, char **buf)
{
	struct rio_tx *tx;

	BUG_ON(cd_list_empty(&dev->free_txs)); /* TODO: grow on demand */
	tx = cd_list_first_entry(&dev->free_txs, struct rio_tx, list);
	cd_list_del(&tx->list);

	BUG_ON(tx->tx_state != TX_FREE);

	tx->tx_state = TX_MSG_DONE;
	tx->xid = 0;

	*buf = dev->tx_bufs + (tx - dev->tx_descs) * RIO_MSG_SIZE;
	return tx;
}

static void rio_put_tx(struct pcs_rdma_device *dev, struct rio_tx *tx)
{
	BUG_ON(tx->tx_state == TX_FREE);

	if (tx->mr) {
		rio_mr_free(tx->mr, dev->pd);
		tx->mr = NULL;
	}
	if (tx->bbuf) {
		pcs_mr_free(tx->bbuf);
		tx->bbuf = NULL;
	}
	tx->msg = NULL;
	tx->xid = 0;
	tx->tx_state = TX_FREE;

	cd_list_add(&tx->list, &dev->free_txs);
}

static void rio_abort(struct pcs_rdmaio *rio, int error)
{
	struct pcs_netio *netio = &rio->netio;

	if (rio->rio_state == RIO_STATE_ABORTED) /* already handled  */
		return;

	if (rio->rio_state == RIO_STATE_ESTABLISHED && rdma_disconnect(rio->cmid))
		pcs_log_errno("rio_abort", "rdma_disconnect");

	rio->rio_state = RIO_STATE_ABORTED;

	while (!cd_list_empty(&rio->write_queue)) {
		struct pcs_msg * msg = rio_dequeue_msg(rio);

		pcs_msg_sent(msg);
		pcs_set_local_error(&msg->error, error);
		msg->done(msg);
	}

	while (!cd_list_empty(&rio->reserved_queue)) {
		struct pcs_msg * msg = rio_dequeue_reserved_msg(rio);

		pcs_msg_sent(msg);
		pcs_set_local_error(&msg->error, error);
		msg->done(msg);
	}

	while (!cd_list_empty(&rio->active_txs)) {
		struct rio_tx *tx = cd_list_first_entry(&rio->active_txs, struct rio_tx, list);
		cd_list_del(&tx->list);

		BUG_ON(!tx->msg);
		pcs_set_local_error(&tx->msg->error, error);
		rio_msg_sent(rio, NULL, tx->msg, 1);
		rio_put_tx(rio->dev, tx);
	}

	pcs_ioconn_unregister(&rio->compc);
	pcs_ioconn_unregister(&netio->ioconn);

	if (netio->eof) {
		void (*eof)(struct pcs_netio *) = netio->eof;
		netio->eof = NULL;
		(*eof)(netio);
	}
}

static void rio_cm_data_ready(struct pcs_ioconn *conn)
{
	struct pcs_rdmaio *rio = rio_from_ioconn(conn);
	struct rdma_cm_event *ev;
	enum rdma_cm_event_type event;
	int status;

	if (rdma_get_cm_event(rio->cmid->channel, &ev)) {
		pcs_log_errno("rio_cm_data_ready", "rdma_get_cm_event");
		rio_abort(rio, PCS_ERR_NET_ABORT);
		return;
	}

	event = ev->event;
	status = ev->status;
	rdma_ack_cm_event(ev);

	switch (event) {
	case RDMA_CM_EVENT_DISCONNECTED:
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		pcs_log_event("rio_cm_data_ready", event, status);

		if (rio->rio_state != RIO_STATE_ABORTED) /* don't call rdma_disconnect() */
			rio->rio_state = RIO_STATE_DISCONNECTED;

		rio_abort(rio, PCS_ERR_NET_ABORT);
		break;
	default:
		pcs_log_event("rio_cm_data_ready", event, status);
	}
}

static int rio_poll_cq(struct ibv_cq *cq, struct ibv_wc *wc)
{
	int ne = ibv_poll_cq(cq, 1, wc);

	if (ne != 1 && ne > 0)
		pcs_fatal("Unexpected rc from ibv_poll_cq: %d", ne);

	return ne;
}

/*
 * Loop until either got a work completion or explicit EAGAIN.
 * See rdma-core/librdmacm/rdma_verbs.h::rdma_get_recv_comp()
 */
static int rio_get_comp(struct pcs_rdmaio *rio, struct ibv_wc *wc)
{
	struct ibv_cq *cq = rio->cq;
	void *ctx;
	int ret;

	for (;;) {
		ret = rio_poll_cq(cq, wc);
		if (ret) {
			if (ret < 0)
				pcs_log_errno("rio_get_comp", "ibv_poll_cq");
			break;
		}

		ret = ibv_req_notify_cq(cq, 0);
		if (ret) {
			pcs_log_errno("rio_get_comp", "ibv_req_notify_cq");
			break;
		}

		ret = rio_poll_cq(cq, wc);
		if (ret) {
			if (ret < 0)
				pcs_log_errno("rio_get_comp", "ibv_poll_cq");
			break;
		}

		ret = ibv_get_cq_event(rio->cc, &cq, &ctx);
		if (ret) {
			if (errno == EAGAIN)
				ret = 0;
			else
				pcs_log_errno("rio_get_comp", "ibv_get_cq_event");
			break;
		}

		BUG_ON(cq != rio->cq);
		ibv_ack_cq_events(cq, 1);
	}

	return ret;
}

enum {
	SUBMIT_REGULAR,
	SUBMIT_NOOP,
	SUBMIT_RDMA_READ_ACK,
};

#define RDMA_THRESHOLD (5*1024)
static int msg_is_large(struct pcs_msg *msg)
{
	int hdr_len = sizeof(struct pcs_rdmaio_hdr);
	return msg->size + hdr_len > RDMA_THRESHOLD;
}

static int rio_init_msg(char *buf, int payload_size, int credits, int submit_type,
			struct pcs_remote_buf **rb, struct pcs_rdma_ack **rack)
{
	struct pcs_rdmaio_hdr *hdr = (struct pcs_rdmaio_hdr *)buf;
	int hdr_len = sizeof(*hdr);
	int type = RIO_MSG_IMMEDIATE;
	int addon_len = 0;

	switch (submit_type) {
	case SUBMIT_NOOP:
		type = RIO_MSG_NOOP;
		break;
	case SUBMIT_REGULAR:
		if (hdr_len + payload_size > RDMA_THRESHOLD) {
			type = RIO_MSG_RDMA_READ_REQ;
			*rb = (struct pcs_remote_buf *)(buf + hdr_len);
			addon_len = sizeof(struct pcs_remote_buf);
		}
		break;
	case SUBMIT_RDMA_READ_ACK:
		type = RIO_MSG_RDMA_READ_ACK;
		*rack = (struct pcs_rdma_ack *)(buf + hdr_len);
		addon_len = sizeof(struct pcs_rdma_ack);
		break;
	default:
		BUG();
	}

	hdr->magic   = RIO_MAGIC;
	hdr->version = RIO_VERSION;
	hdr->type    = type;
	hdr->size    = hdr_len + addon_len;
	hdr->credits = credits;

	return hdr->size;
}

static void rio_update_msg_immediate(char *buf, int copied)
{
	struct pcs_rdmaio_hdr *hdr = (struct pcs_rdmaio_hdr *)buf;

	hdr->size += copied;
}

#define MAX_SGE_IDX 2

static void rio_submit(struct pcs_rdmaio *rio, struct pcs_msg *msg, int type, u64 xid, int status)
{
	struct pcs_rdma_device *dev      = rio->dev;
	char                   *tx_buf;
	struct rio_tx          *tx       = rio_get_tx(dev, &tx_buf);
	void                   *ctx      = rio_wr_id_build(tx, RIO_TX_COMPL);
	int                     credits  = rio->n_os_credits;
	int                     msg_size = msg ? msg->size : 0;
	struct pcs_remote_buf  *rb       = NULL;
	int                     rb_set   = 0; /* boolean flag; for sanity */
	struct pcs_rdma_ack    *rack     = NULL;
	int                     hdr_len  = rio_init_msg(tx_buf, msg_size, credits, type, &rb, &rack);
	char                   *payload  = tx_buf + hdr_len;
	int offset = 0, bbuf_offset = 0;

	struct ibv_sge sge[MAX_SGE_IDX];
	int idx = 0;

	sge[0].addr   = (uint64_t) (uintptr_t) tx_buf;
	sge[0].length = hdr_len;
	sge[0].lkey   = dev->tx_mr->lkey;

	if (rack) {
		rack->xid    = xid;
		rack->status = status;
	} else if (rb) {
		rio->xid_generator++;
		rb->xid = tx->xid = rio->xid_generator;
		tx->tx_state = TX_WAIT_FOR_TX_COMPL;
	}

	struct ibv_mr *mr  = NULL;
	while (offset < msg_size) {
		void *buf, *sbuf;
		int copy, scopy;

		buf = sbuf = msg->get_chunk(msg, offset, &copy);
		scopy = copy;

		BUG_ON(copy <= 0 && copy != -PCS_MR_POOL_BUF);
		BUG_ON(idx > 0 && copy > 0);

		unwind_mr_buf(&buf, &copy);
		if (copy > msg_size - offset)
			copy = msg_size - offset;

		/* data is split between multiple memory regions, have to use bounce buffer */
		if (((hdr_len + offset + copy) > RDMA_THRESHOLD && (offset + copy) < msg_size) || tx->bbuf) {
			if (!tx->bbuf) {
				struct pcs_mr_buf mr_buf;

				tx->bbuf = pcs_mr_xmalloc(msg_size - offset);
				mr_buf.buf = tx->bbuf;
				mr_buf.size = msg_size - offset;
				mr_buf.ctx = pcs_mr_get_ctx(tx->bbuf);

				BUG_ON(rio_mr_alloc(rio, &mr_buf, -PCS_MR_POOL_BUF, &mr));
			}
			memcpy(tx->bbuf + bbuf_offset, buf, copy);
			bbuf_offset += copy;
			offset += copy;
			pcs_rdmaio_stats.bounce_buf_total += copy;
			continue;
		}

		if ((scopy == -PCS_MR_POOL_BUF) || (hdr_len + offset + copy > RDMA_THRESHOLD)) {
			if (rio_mr_alloc(rio, sbuf, scopy, &mr))
				tx->mr = mr;

			if (hdr_len + offset + copy > RDMA_THRESHOLD) {
				BUG_ON(!rb);
				BUG_ON(rb_set);

				rb->rbuf = (uint64_t) (uintptr_t) buf;
				rb->rkey = mr->rkey;
				rb->rlen = copy;
				rb_set   = 1;
			} else {
				idx++;
				BUG_ON(idx == MAX_SGE_IDX);
				BUG_ON(rb_set);

				sge[idx].addr   = (uint64_t) (uintptr_t) buf;
				sge[idx].length = copy;
				sge[idx].lkey   = mr->lkey;
			}
		} else {
			BUG_ON(idx != 0);
			BUG_ON(rb_set);

			memcpy(payload + offset, buf, copy);
			sge[0].length += copy;
		}

		offset += copy;
		if (!rb_set)
			rio_update_msg_immediate(tx_buf, copy);
	}
	if (tx->bbuf) {
		BUG_ON(!rb);
		BUG_ON(rb_set);

		rb->rbuf = (uint64_t) (uintptr_t) tx->bbuf;
		rb->rkey = mr->rkey;
		rb->rlen = bbuf_offset;
		rb_set   = 1;
	}

	BUG_ON(rb && !rb_set); /* if rb is wanted, we must have set it */

	if (rdma_post_sendv(rio->cmid, ctx, sge, idx + 1, IBV_SEND_SIGNALED)) {
		pcs_log_errno("rio_submit", "rdma_post_sendv");
		rio_put_tx(dev, tx);
		if (msg)
			cd_list_add(&msg->list, &rio->write_queue);
		rio->write_queue_len++;
		rio_abort(rio, PCS_ERR_NET_ABORT);
		return;
	}

	rio->n_os_credits -= credits;
	rio->n_tx_posted++;
	if (msg) {
		rio->n_peer_credits--;
		if (rb_set)
			rio->n_reserved_credits--;
		BUG_ON(rio->n_peer_credits < 0);
		BUG_ON(rio->n_reserved_credits < 0);

		/*
		 * It's possible to see RX completion for response to this message
		 * *before* we see TX completion for this message. This will result
		 * in RPC's handle_response failing to find corresponding TX by xid.
		 *
		 * Thus, we shouldn't wait for TX completion to tell upper layer that
		 * the message has been sent and do it right after
		 * rdma_post_sendv completes (similar to TCP). If
		 * rdma_post_sendv() fails eventually, we will receive TX
		 * completion with an error flag and cancel all
		 * outstanding/pending RPC requests. So we are not going to
		 * lose an error.
		 *
		 * But, if the message is big enough to trigger RDMA READ
		 * transfer, we are going to call ->done() callback after we
		 * receive RDMA_READ_ACK message from our peer. Since messages
		 * in a single RX queue are guaranteed to come in order, there
		 * is no race in this case.
		 */
		rio_msg_sent(rio, tx, msg, rb == NULL);
	}
}

struct pcs_rdma_desc {
	struct pcs_msg *msg; /* call msg->done(msg) when RDMA-transfer is done */
	struct ibv_mr *mr; /* mr handler for on-demand mapping */
	uint64_t xid;
	uint64_t laddr;
	uint64_t raddr;
	uint32_t lkey;
	uint32_t rkey;
	int len;
};

static void rio_submit_rdma(struct pcs_rdmaio *rio, struct pcs_rdma_desc *rd)
{
	struct pcs_rdma_device *dev      = rio->dev;
	char                   *tx_buf;
	struct rio_tx          *tx       = rio_get_tx(dev, &tx_buf);
	void                   *ctx      = rio_wr_id_build(tx, RIO_TX_COMPL);
	struct ibv_sge sge;

	tx->tx_state = TX_SUBMIT_RDMA_READ_ACK;

	sge.addr   = rd->laddr;
	sge.length = rd->len;
	sge.lkey   = rd->lkey;

	if (rdma_post_readv(rio->cmid, ctx, &sge, 1, IBV_SEND_SIGNALED, rd->raddr, rd->rkey)) {
		pcs_log_errno("rio_submit_rdma", "rdma_post_readv");
		rio_put_tx(dev, tx);
		pcs_free_msg(rd->msg);
		rio_abort(rio, PCS_ERR_NET_ABORT);
		return;
	}

	rio->n_tx_posted++;
	tx->mr = rd->mr;
	tx->msg = rd->msg;
	tx->xid = rd->xid;
}

static void rio_kick_write_queue(struct pcs_rdmaio *rio)
{
	/* Nothing to do if rio destroy is already in progress */
	if (rio->errored || rio->rio_state == RIO_STATE_ABORTED) {
		BUG_ON(!cd_list_empty(&rio->write_queue));
		BUG_ON(!cd_list_empty(&rio->reserved_queue));
		return;
	}

	/* pcs_rpc won't switch to ep->state == PCS_RPC_WORK until we
	 * switch to rio->rio_state == RIO_STATE_ESTABLISHED, and if
	 * we got disconnected, rio_abort() drains write_queue and
	 * moves us to RIO_STATE_ABORTED -- see check above */
	BUG_ON(rio->rio_state != RIO_STATE_ESTABLISHED);

	/* NB: n_tx_posted is not # msg in flihgt, it is # msg
	 * whose (local) send operation is in progress */
	if (rio->n_tx_posted >= rio->queue_depth)
		return;

	/* Return credits by NOOP only if we have many enough to return AND
	 * we cannot piggyback it by sending a message from write_queue */
	if (rio->n_os_credits >= rio->n_th_credits &&
	    ((cd_list_empty(&rio->write_queue) &&
	      (cd_list_empty(&rio->reserved_queue) || !rio->n_reserved_credits)) ||
	     !rio->n_peer_credits)) {
		rio_submit(rio, NULL, SUBMIT_NOOP, 0, 0);
		return;
	}

	/* Main loop sending large messages from reserved_queue */
	while (!cd_list_empty(&rio->reserved_queue) && rio->n_peer_credits &&
	       rio->n_reserved_credits) {
		struct pcs_msg *msg = rio_dequeue_reserved_msg(rio);
		rio_submit(rio, msg, SUBMIT_REGULAR, 0, 0);
	}

	/* Main loop sending ordinary messages from write_queue */
	while (!cd_list_empty(&rio->write_queue) && rio->n_peer_credits) {
		struct pcs_msg *msg = rio_dequeue_msg(rio);

		if (!rio->n_reserved_credits && msg_is_large(msg)) {
			cd_list_add_tail(&msg->list, &rio->reserved_queue);
			rio->reserved_queue_len++;
		} else {
			rio_submit(rio, msg, SUBMIT_REGULAR, 0, 0);
		}
	}
}

/*
 * A helper to be called on RX/TX completion when rio->errored
 */
static void rio_handle_errored(struct pcs_rdmaio *rio)
{
	if (rio->n_rx_posted + rio->n_tx_posted == 0)
		pcs_ioconn_unregister(&rio->compc);
}

static void rdma_desc_build(struct pcs_rdmaio *rio, struct pcs_msg *msg,
			    int offset, struct pcs_remote_buf *rb,
			    struct pcs_rdma_desc *rd)
{
	int body_len = 0;
	void *body = msg->get_chunk(msg, offset, &body_len);
	struct ibv_mr     *mr;

	BUG_ON(!rb);

	if (rio_mr_alloc(rio, body, body_len, &mr))
		rd->mr = mr;
	unwind_mr_buf(&body, &body_len);
	BUG_ON(body_len < rb->rlen); // TODO: handle this as error (crap from the network)

	rd->msg = msg;
	rd->xid = rb->xid;
	rd->len = rb->rlen;

	rd->laddr = (uint64_t) (uintptr_t) body;
	rd->lkey  = mr->lkey;

	rd->raddr = rb->rbuf;
	rd->rkey  = rb->rkey;
}

/*
 * rio wire header is already stripped, buf points to payload data (pcs_rpc hdr)
 */
static int rio_handle_rx_immediate(struct pcs_rdmaio *rio, char *buf, int len,
				   struct pcs_remote_buf *rb, int *throttle,
				   struct pcs_rdma_desc *rd)
{
	struct pcs_msg *msg;
	int offset = rio->hdr_size;
	int leftover = 0;

	if (len < rio->hdr_size) {
		pcs_log(LOG_ERR, "rio read short msg: %d < %d", len, rio->hdr_size);
		return PCS_ERR_NET_ABORT;
	}

	msg = rio->netio.getmsg(&rio->netio, buf);
	if (msg == NULL) {
		int err = 0;
		if (rio->throttled)
			*throttle = 1;
		else
			err = PCS_ERR_NOMEM;
		return err;
	}

	if (msg->size != len + (rb ? rb->rlen : 0)) {
		pcs_log(LOG_ERR, "rio read wrong len: %d != %d (%lx/%x/%d)", len, msg->size,
			rb ? rb->rbuf : 0, rb ? rb->rkey : 0, rb ? rb->rlen : -1);
		pcs_free_msg(msg);
		return PCS_ERR_NET_ABORT;
	}

	while (offset < len) {
		int body_len = 0;
		void *body = msg->get_chunk(msg, offset, &body_len);

		/* Yeah... mr_buf is useless if payload is sent w/o RDMA */
		unwind_mr_buf(&body, &body_len);

		if (body_len > len - offset) {
			leftover = body_len - (len - offset);
			body_len = len - offset;
		}

		memcpy(body, buf + offset, body_len);
		offset += body_len;
	}

	/* handling non-zero leftover is doable but hard; postpone it until really needed */
	BUG_ON(len != msg->size && leftover);

	if (len == msg->size)
		msg->done(msg);
	else
		rdma_desc_build(rio, msg, offset, rb, rd);

	return 0;
}

static void rio_handle_tx(struct pcs_rdmaio *rio, struct rio_tx *tx, int ok);

/*
 * When we see RX coming from the wire very first time, flag "pended" is
 * false and we naturally update n_rx_posted and n_peer_credits.
 *
 * Later on, due to throttling, the RX may reside in pended_rxs for a while.
 * Then, handling unthrottle event, we will see this RX again, the "pended"
 * flag is true. This means we should not touch n_rx_posted and
 * n_peer_credits again.
 */
static void rio_handle_rx(struct pcs_rdmaio *rio, struct rio_rx *rx, int status, int pended)
{
	char *buf          = rx2buf(rio, rx);
	int   ok           = (status == IBV_WC_SUCCESS) && (rio->rio_state != RIO_STATE_ABORTED);
	char *payload      = NULL;
	int   payload_size = 0;
	int   credits      = 0;
	int   throttle     = 0;
	int   type;
	int   err = PCS_ERR_NET_ABORT;
	struct pcs_remote_buf *rb   = NULL;
	struct pcs_rdma_ack   *rack = NULL;
	struct pcs_rdma_desc   rd   = { .msg = NULL };
	struct rio_tx         *tx;

	BUG_ON(rio->errored && ok);

	if (!pended) {
		rio->n_rx_posted--;
		BUG_ON(rio->n_rx_posted < 0);
	}

	if (!ok) {
		if (rio->errored)
			rio_handle_errored(rio);
		else
			rio_abort(rio, PCS_ERR_NET_ABORT);
		return;
	}

	BUG_ON(rio->rio_state != RIO_STATE_ESTABLISHED); /* early rx? */

	type = rio_parse_hdr(buf, &payload, &payload_size, &credits, &rb, &rack);

	rio->no_kick = 1;
	switch (type) {
	case RIO_MSG_IMMEDIATE:
	case RIO_MSG_RDMA_READ_REQ:
		err = rio_handle_rx_immediate(rio, payload, payload_size, rb, &throttle, &rd);
		if (err)
			goto do_abort;
		break;
	case RIO_MSG_NOOP:
		/* for now, it only returns credits */
		break;
	case RIO_MSG_RDMA_READ_ACK:
		BUG_ON(!rack);
		BUG_ON(cd_list_empty(&rio->active_txs));
		tx = cd_list_first_entry(&rio->active_txs, struct rio_tx, list);
		cd_list_del(&tx->list);
		BUG_ON(tx->xid != rack->xid);
		rio_handle_tx(rio, tx, !rack->status);
		break;
	default:
		goto do_abort;
	}
	rio->no_kick = 0;

	if (!throttle) {
		void *ctx = rio_wr_id_build(rx, RIO_RX_COMPL);
		if (rdma_post_recv(rio->cmid, ctx, buf, RIO_MSG_SIZE, rio->rx_mr)) {
			pcs_log_errno("rio_handle_rx", "rdma_post_recv");
			rio_abort(rio, PCS_ERR_NET_ABORT);
			return;
		}
		rio->n_rx_posted++;

		if (type != RIO_MSG_NOOP &&
		    type != RIO_MSG_RDMA_READ_ACK)
			rio->n_os_credits++;

		if (type == RIO_MSG_RDMA_READ_ACK)
			rio->n_reserved_credits++;

		BUG_ON(rio->n_os_credits > rio->queue_depth);
		BUG_ON(rio->n_reserved_credits > rio->queue_depth);
	} else
		cd_list_add(&rx->list, &rio->pended_rxs);

	if (!pended)
		rio->n_peer_credits += credits;

	if (rd.msg)
		rio_submit_rdma(rio, &rd);

	rio_kick_write_queue(rio);
	return;

do_abort:
	rio->no_kick = 0; /* only for sanity */
	rio_abort(rio, err);
}

static void rio_handle_pended_rxs(struct pcs_rdmaio *rio)
{
	struct cd_list local;

	cd_list_init(&local);
	cd_list_splice(&rio->pended_rxs, &local);

	while (!cd_list_empty(&local)) {
		struct rio_rx *rx;
		int status = rio->errored ? IBV_WC_FATAL_ERR : IBV_WC_SUCCESS;

		rx = cd_list_first_entry(&local, struct rio_rx, list);
		cd_list_del(&rx->list);

		rio_handle_rx(rio, rx, status, 1);
	}
}

static void rio_handle_tx(struct pcs_rdmaio *rio, struct rio_tx *tx, int ok)
{
	struct pcs_msg *msg = NULL;

	/* override remote success if we already errored */
	if (rio->errored || rio->rio_state == RIO_STATE_ABORTED)
		ok = 0;

	switch (tx->tx_state) {
		case TX_SUBMIT_RDMA_READ_ACK:
			rio_submit(rio, NULL, SUBMIT_RDMA_READ_ACK, tx->xid, !ok);
			break;
		case TX_WAIT_FOR_TX_COMPL:
		case TX_WAIT_FOR_READ_ACK:
			if (!ok)
				break;
			if (++tx->tx_state != TX_MSG_DONE)
				return;
		case TX_MSG_DONE:
		case TX_FREE:
			break;
		default:
			BUG();
	}

	if (!ok) {
		if (rio->errored)
			rio_handle_errored(rio);
		else
			rio_abort(rio, PCS_ERR_NET_ABORT);
	}

	msg = tx->msg;
	if (tx->tx_state != TX_FREE)
		rio_put_tx(rio->dev, tx);
	if (msg) {
		if (!ok)
			pcs_set_local_error(&msg->error, PCS_ERR_NET_ABORT);

		rio_msg_sent(rio, NULL, msg, 1);
	}

	if (ok)
		rio_kick_write_queue(rio);
}

static void rio_cc_data_ready(struct pcs_ioconn *conn)
{
	struct pcs_rdmaio *rio = rio_from_compc(conn);

	for (;;) {
		struct ibv_wc wc = { .wr_id = 0 };
		void *ctx;
		int ret, type;

		ret = rio_get_comp(rio, &wc);
		if (ret < 0) {
			rio_abort(rio, PCS_ERR_NET_ABORT);
			return;
		}

		if (!ret) /* nothing more to do */
			return;


		ctx = rio_wr_id_split(wc.wr_id, &type);
		if (wc.status && !rio->errored &&
		    rio->rio_state != RIO_STATE_ABORTED)
			pcs_log(LOG_ERR, "rio: wc of type=%d completed with status=%d (state=%d)",
				type, wc.status, rio->rio_state);
		switch (type) {
		case RIO_RX_COMPL:
			rio_handle_rx(rio, ctx, wc.status, 0);
			break;
		case RIO_TX_COMPL:
			rio->n_tx_posted--;
			BUG_ON(rio->n_tx_posted < 0);
			rio_handle_tx(rio, ctx, wc.status == IBV_WC_SUCCESS);
			break;
		default:
			BUG();
		}
	}
}

static struct pcs_rdma_device *rio_get_dev(struct ibv_context *verbs)
{
	struct pcs_rdma_device *dev;
	struct rio_tx          *tx;

	int tx_descs_siz = RIO_N_TXS_PER_DEV * sizeof(struct rio_tx);
	int tx_bufs_siz  = RIO_N_TXS_PER_DEV * RIO_MSG_SIZE;
	BUG_ON(tx_descs_siz / sizeof(struct rio_tx) != tx_bufs_siz / RIO_MSG_SIZE);

	cd_list_for_each_entry(struct pcs_rdma_device, dev, &pcs_rdma_devices, list)
		if (dev->verbs == verbs)
			return dev;

	dev = pcs_malloc(sizeof(*dev));
	if (!dev)
		return NULL;
	memset(dev, 0, sizeof(*dev));

	dev->tx_descs = pcs_malloc(tx_descs_siz);
	if (!dev->tx_descs)
		goto free_dev;
	memset(dev->tx_descs, 0, tx_descs_siz);

	dev->tx_bufs = pcs_malloc(tx_bufs_siz);
	if (!dev->tx_bufs)
		goto free_dev;

	cd_list_init(&dev->free_txs);
	for (tx = dev->tx_descs; tx - dev->tx_descs < RIO_N_TXS_PER_DEV; tx++)
		cd_list_add(&tx->list, &dev->free_txs);

	dev->pd = ibv_alloc_pd(verbs);
	if (!dev->pd) {
		pcs_log_errno("rio_get_pd", "ibv_alloc_pd");
		goto free_dev;
		return NULL;
	}

	dev->tx_mr = ibv_reg_mr(dev->pd, dev->tx_bufs, tx_bufs_siz,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_WRITE);
	if (!dev->tx_mr) {
		pcs_log_errno("rio_get_dev", "ibv_reg_mr");
		goto free_dev;
	}

	dev->verbs = verbs;
	cd_list_add(&dev->list, &pcs_rdma_devices);
	return dev;

free_dev:
	if (dev->pd)
		ibv_dealloc_pd(dev->pd);
	if (dev->tx_descs)
		pcs_free(dev->tx_descs);
	if (dev->tx_bufs)
		pcs_free(dev->tx_bufs);
	pcs_free(dev);
	return NULL;
}

struct pcs_rdmaio *
rio_create(struct pcs_process * proc, int hdr_size,
	   struct rdma_cm_id *cmid, int queue_depth)
{
	struct pcs_rdmaio       *rio;
	struct pcs_rdma_device  *dev;
	struct ibv_comp_channel	*cc;
	struct ibv_cq		*cq;
	struct ibv_mr           *mr;
	struct rio_rx           *rx;
	struct ibv_qp_init_attr	 qp_attr = {};
	int rx_descs_siz = RIO_N_RXS * sizeof(struct rio_rx);
	int rx_bufs_siz  = RIO_N_RXS * RIO_MSG_SIZE;

	rio = pcs_malloc(sizeof(struct pcs_rdmaio));
	if (!rio)
		return NULL;
	memset(rio, 0, sizeof(*rio));

	rio->rx_descs = pcs_malloc(rx_descs_siz);
	if (!rio->rx_descs)
		goto free_bufs;
	memset(rio->rx_descs, 0, rx_descs_siz);

	rio->rx_bufs = pcs_malloc(rx_bufs_siz);
	if (!rio->rx_bufs)
		goto free_bufs;
	memset(rio->rx_bufs, 0, rx_bufs_siz);

	cd_list_init(&rio->pended_rxs);
	cd_list_init(&rio->write_queue);
	cd_list_init(&rio->reserved_queue);
	cd_list_init(&rio->active_txs);
	rio->write_queue_len = 0;
	rio->no_kick         = 0;
	rio->throttled       = 0;
	rio->errored         = 0;
	rio->xid_generator   = 0;

	dev = rio_get_dev(cmid->verbs);
	if (!dev)
		goto free_bufs;

	mr = ibv_reg_mr(dev->pd, rio->rx_bufs, rx_bufs_siz,
			IBV_ACCESS_LOCAL_WRITE |
			IBV_ACCESS_REMOTE_READ |
			IBV_ACCESS_REMOTE_WRITE);
	if (!mr) {
		pcs_log_errno("rio_create", "ibv_reg_mr");
		goto free_bufs;
	}

	cc = ibv_create_comp_channel(cmid->verbs);
	if (!cc) {
		pcs_log_errno("rio_create", "ibv_create_comp_channel");
		goto free_mr;
	}

	cq = ibv_create_cq(cmid->verbs, RIO_N_RXS + RIO_N_TXS, NULL, cc, 0);
	if (!cq) {
		pcs_log_errno("rio_create", "ibv_create_cq");
		goto free_cc;
	}

	if (ibv_req_notify_cq(cq, 0)) {
		pcs_log_errno("rio_create", "ibv_req_notify_cq");
		goto free_cq;
	}

	qp_attr.cap.max_send_wr	 = RIO_N_TXS;
	qp_attr.cap.max_send_sge = MAX_SGE_IDX;
	qp_attr.cap.max_recv_wr	 = RIO_N_RXS;
	qp_attr.cap.max_recv_sge = MAX_SGE_IDX;
	qp_attr.send_cq		 = cq;
	qp_attr.recv_cq		 = cq;
	qp_attr.qp_type		 = IBV_QPT_RC;

	if (rdma_create_qp(cmid, dev->pd, &qp_attr)) {
		if (errno != EINVAL)
			pcs_log_errno("rio_create", "rdma_create_qp");
		goto free_cq;
	}

	rio->proc = proc;
	rio->hdr_size = hdr_size;
	rio->rio_state = RIO_STATE_CONNECTING;
	rio->queue_depth = queue_depth;

	rio->cmid =  cmid;
	rio->dev  =  dev;
	rio->cc   =  cc;
	rio->cq   =  cq;
	rio->rx_mr = mr;

	rio->conn_req.magic       = RIO_MAGIC;
	rio->conn_req.version     = RIO_VERSION;
	rio->conn_req.queue_depth = queue_depth;
	rio->conn_req.msg_size    = RIO_MSG_SIZE;

	rio->n_peer_credits = queue_depth;
	rio->n_reserved_credits = queue_depth;
	rio->n_th_credits   = queue_depth / 2;
	rio->n_os_credits   = 0;

	for (rx = rio->rx_descs; rx - rio->rx_descs < RIO_N_RXS; rx++) {
		void *ctx    = rio_wr_id_build(rx, RIO_RX_COMPL);
		char *rx_buf = rx2buf(rio, rx);

		if (rdma_post_recv(cmid, ctx, rx_buf, RIO_MSG_SIZE, mr)) {
			pcs_log_errno("rio_create", "rdma_post_recv");
			break;
		}
		rio->n_rx_posted++;
	}

	if (!rio->n_rx_posted) /* release everything but cmid */
		goto free_qp;

	if (rio->n_rx_posted != RIO_N_RXS)
		rio_destroy(rio); /* caller must check rio->errored */

	return rio;

free_qp:
	rdma_destroy_qp(cmid);
free_cq:
	ibv_destroy_cq(cq);
free_cc:
	ibv_destroy_comp_channel(cc);
free_mr:
	ibv_dereg_mr(mr);
free_bufs:
	if (rio->rx_descs)
		pcs_free(rio->rx_descs);
	if (rio->rx_bufs)
		pcs_free(rio->rx_bufs);
	pcs_free(rio);
	return NULL;
}

static void rio_free(struct pcs_ioconn *conn)
{
	struct pcs_rdmaio *rio = rio_from_compc(conn);
	struct rdma_event_channel *cmc;

	rdma_destroy_qp(rio->cmid);
	ibv_destroy_cq(rio->cq);
	ibv_destroy_comp_channel(rio->cc);
	ibv_dereg_mr(rio->rx_mr);
	cmc = rio->cmid->channel;
	rdma_destroy_id(rio->cmid);
	rdma_destroy_event_channel(cmc);

	rio->proc->sio_count--;
	pcs_free(rio->rx_descs);
	pcs_free(rio->rx_bufs);
	pcs_free(rio);
}

void rio_destroy(struct pcs_rdmaio *rio)
{
	struct pcs_ioconn *conn = &rio->compc;
	struct ibv_qp_attr qp_attr = { .qp_state = IBV_QPS_ERR };

	/*
	 * There are three possible cases to be here:
	 * 1) rio_create failed, then we have at least one RX posted;
	 * 2) rio_create succeeded, then we have RIO_N_RXS posted;
	 * 3) something went wrong in the middle of handling RX, in that
	 * moment we had RIO_N_RXS-1 posted, then rio_abort is called,
	 * rio_abort called rdma_disconnect, which, in turn, triggered
	 * completion of all posted RXs with error status. Hence, by the
	 * time rio_destroy is called, rio->n_rx_posted is already 0. */
	if (rio->n_rx_posted + rio->n_tx_posted == 0) {
		rio_free(conn);
		return;
	}
	/*
	 * If we got here because of REJECTED event the queue is already in
	 * IBV_QP_STATE == IBV_QPS_ERR and no rx_completion events will be
	 * triggered (as no event handler was installed at that moment).  Thus,
	 * just kill it right away.
	 * Also, rely on the state stored in qp struct instead of queried from
	 * device, as, for example, i40iw doesn't return it at all...
	 */
	if (!rio->errored && rio->n_tx_posted == 0 && rio->cmid->qp->state == IBV_QPS_ERR) {
		rio_free(conn);
		return;
	}

	if (ibv_modify_qp(rio->cmid->qp, &qp_attr, IBV_QP_STATE))
		pcs_log_errno("rio_destroy", "ibv_modify_qp");

	rio->errored = 1; /* rdma engine is not usable anymore */

	pcs_sock_nonblock(rio->cc->fd);
	pcs_ioconn_init(rio->proc, conn);
	conn->fd = rio->cc->fd;
	conn->destruct = rio_free;
	conn->data_ready = rio_cc_data_ready;
	conn->next_mask = POLLIN;
	pcs_ioconn_register(conn);
}

static void rio_destruct(struct pcs_rdmaio *rio)
{
	if (--rio->refcnt)
		return;

	rio_destroy(rio);
}

static void rio_cm_destruct(struct pcs_ioconn *conn)
{
	rio_destruct(rio_from_ioconn(conn));
}

static void rio_cc_destruct(struct pcs_ioconn *conn)
{
	rio_destruct(rio_from_compc(conn));
}

void rio_ioconn_init(struct pcs_rdmaio *rio)
{
	struct pcs_ioconn *conn;

	conn = &rio->netio.ioconn;
	pcs_sock_nonblock(rio->cmid->channel->fd);
	pcs_ioconn_init(rio->proc, conn);
	conn->fd = rio->cmid->channel->fd;
	conn->destruct = rio_cm_destruct;
	conn->data_ready = rio_cm_data_ready;
	conn->next_mask = POLLIN;

	conn = &rio->compc;
	pcs_sock_nonblock(rio->cc->fd);
	pcs_ioconn_init(rio->proc, conn);
	conn->fd = rio->cc->fd;
	conn->destruct = rio_cc_destruct;
	conn->data_ready = rio_cc_data_ready;
	conn->next_mask = POLLIN;

	rio->refcnt = 2;  /* one for netio.ioconn and one for compc */
	rio->proc->sio_count++;
	rio->netio.tops = &netio_tops;
	rio->rio_state = RIO_STATE_ESTABLISHED;
}


/* netio transport operations */

static void rio_register(struct pcs_netio *netio)
{
	struct pcs_rdmaio *rio = rio_from_netio(netio);

	pcs_ioconn_register(&netio->ioconn);
	pcs_ioconn_register(&rio->compc);
}

static void rio_throttle(struct pcs_netio *netio)
{
	struct pcs_rdmaio *rio = rio_from_netio(netio);

	if (rio->throttled || netio->ioconn.dead)
		return;

	rio->throttled = 1;
}

static void rio_unthrottle(struct pcs_netio *netio)
{
	struct pcs_rdmaio *rio = rio_from_netio(netio);

	if (!rio->throttled || netio->ioconn.dead)
		return;

	rio->throttled = 0;

	if (!cd_list_empty(&rio->pended_rxs))
		rio_handle_pended_rxs(rio);
}

static void rio_sendmsg(struct pcs_netio *netio, struct pcs_msg *msg)
{
	struct pcs_rdmaio *rio = rio_from_netio(netio);

	msg->netio = netio;

	cd_list_add_tail(&msg->list, &rio->write_queue);
	rio->write_queue_len++;
	msg->start_time = get_abs_time_fast_ms();
	msg->stage = PCS_MSG_STAGE_SEND;

	if (!rio->no_kick)
		rio_kick_write_queue(rio);
}

static int rio_cancelmsg(struct pcs_msg *msg)
{
	/* Not implemented yet */	
	return -EBUSY;
}

static void rio_abort_wrapper(struct pcs_netio *netio, int error)
{
	struct pcs_rdmaio *rio = rio_from_netio(netio);
	rio_abort(rio, error);
}

static void rio_setup_buffers(struct pcs_netio *netio, int tcp_sndbuf, int tcp_rcvbuf, int local_sndbuf)
{
	/* Nothing to do here */
}

static void rio_trace_health(struct pcs_netio *netio, const char *role, unsigned long long id_val)
{
	/* Not implemented yet */
}

static int rio_getmyname(struct pcs_netio *netio, PCS_NET_ADDR_T * addr)
{
	struct pcs_rdmaio *rio = rio_from_netio(netio);
	struct sockaddr *sa;
	int err;

	if (!rio->cmid)
		return -EINVAL;

	sa = rdma_get_local_addr(rio->cmid);

	err  = pcs_sockaddr2netaddr(addr, sa);
	if (err)
		return err;

	addr->type = PCS_ADDRTYPE_RDMA;
	return 0;
}

static int rio_getpeername(struct pcs_netio *netio, PCS_NET_ADDR_T * addr)
{
	struct pcs_rdmaio *rio = rio_from_netio(netio);
	struct sockaddr *sa;
	int err;

	if (!rio->cmid)
		return -EINVAL;

	sa = rdma_get_peer_addr(rio->cmid);

	err  = pcs_sockaddr2netaddr(addr, sa);
	if (err)
		return err;

	addr->type = PCS_ADDRTYPE_RDMA;
	return 0;
}

static unsigned int rio_get_retrans_stat(struct pcs_netio *netio)
{
	return 0;
}

struct pcs_netio_tops netio_tops = {
	.register_io	= rio_register,
	.throttle	= rio_throttle,
	.unthrottle	= rio_unthrottle,
	.send_msg	= rio_sendmsg,
	.cancel_msg	= rio_cancelmsg,
	.abort_io	= rio_abort_wrapper,
	.setup_buffers	= rio_setup_buffers,
	.trace_health	= rio_trace_health,
	.getmyname	= rio_getmyname,
	.getpeername	= rio_getpeername,
	.get_retrans_stat = rio_get_retrans_stat,
};
