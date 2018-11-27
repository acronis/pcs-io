/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_types.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <unistd.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "pcs_sock_io.h"
#include "pcs_poll.h"
#include "pcs_malloc.h"
#include "pcs_mr_malloc.h"
#include "bufqueue.h"
#include "pcs_errno.h"
#include "pcs_splice.h"
#include "log.h"
#include "bug.h"

#ifdef HAVE_TCP_INFO
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#endif

static struct pcs_netio_tops netio_tops;

void pcs_msg_sent(struct pcs_msg * msg)
{
	msg->stage = PCS_MSG_STAGE_SENT;
	if (msg->timeout) {
		BUG_ON(msg->rpc == NULL);
		BUG_ON(msg->kill_slot >= PCS_MSG_MAX_CALENDAR);
		cd_hlist_del(&msg->kill_link);
		cd_hlist_node_init(&msg->kill_link);
	}
}

void sio_push(struct pcs_sockio * sio)
{
	if (sio->flags & PCS_SOCK_F_CORK)
		pcs_sock_push(sio_sock(sio));
}

void sio_abort(struct pcs_sockio * sio, int error)
{
	if (sio->current_msg) {
		pcs_free_msg(sio->current_msg);
		sio->current_msg = NULL;
	}

	if (sio->splice_wbuf) {
		pcs_splice_buf_put(sio->splice_wbuf);
		sio->splice_wbuf = NULL;
	}

	if (sio->splice_rbuf) {
		pcs_splice_buf_put(sio->splice_rbuf);
		sio->splice_rbuf = NULL;
	}

	while (!cd_list_empty(&sio->write_queue)) {
		struct pcs_msg * msg = cd_list_first_entry(&sio->write_queue, struct pcs_msg, list);
		cd_list_del(&msg->list);
		sio->write_queue_len -= msg->size;
		pcs_msg_sent(msg);

		pcs_set_local_error(&msg->error, error);
		msg->done(msg);
	}

	del_timer_sync(&sio->write_timer);

	sio->netio.ioconn.next_mask = 0;
	pcs_ioconn_schedule(&sio->netio.ioconn);
	pcs_ioconn_close(&sio->netio.ioconn);
	if (sio->msg_count == 0)
		pcs_ioconn_unregister(&sio->netio.ioconn);

	pcs_set_local_error(&sio->error, error);
	if (sio->netio.eof) {
		void (*eof)(struct pcs_netio *) = sio->netio.eof;
		sio->netio.eof = NULL;
		(*eof)(&sio->netio);
	}
}

void pcs_sock_abort(struct pcs_sockio * sio)
{
	if (!sio)
		return;

	sio_abort(sio, PCS_ERR_NET_ABORT);
}

void pcs_sock_error(struct pcs_sockio * sio, int error)
{
	sio_abort(sio, error);
}

static void error_report(struct pcs_ioconn *conn)
{
	struct pcs_sockio * sio = sio_from_ioconn(conn);
	int error;
	socklen_t so_len = sizeof(error);

	if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, (char*)&error, &so_len))
		error = EINVAL;

	sio_abort(sio, PCS_ERR_NET_ABORT);
}

static void data_ready(struct pcs_ioconn *conn)
{
	struct pcs_sockio * sio = sio_from_ioconn(conn);
	int count = 0;

	while (!pcs_if_error(&sio->error)) {
		int n;
		struct pcs_msg * msg;

		if (sio->flags & (PCS_SOCK_F_THROTTLE|PCS_SOCK_F_EOF)) {
			conn->next_mask &= ~POLLIN;
			break;
		}

		if (!sio->current_msg) {
			int copy = (int)(sio->hdr_max - sio->hdr_ptr);
			sio->read_offset = 0;
			n = 0;
			if (copy)
				n = recv(conn->fd, (char *)sio_inline_buffer(sio) + sio->hdr_ptr, copy, MSG_DONTWAIT);
			if (n > 0 || n == copy /* recv return 0 when copy is 0 */) {
				BUG_ON(n < 0);
				sio->hdr_ptr += n;
				if (!(sio->flags & PCS_SOCK_F_DYNAMIC_SIZE) &&
				    sio->hdr_ptr != sio->hdr_max)
					return;
				msg = sio->netio.getmsg(&sio->netio, sio->_inline_buffer);
				if (msg == NULL) {
					if (sio->hdr_ptr < sio->hdr_max)
						continue;
					if (sio->flags & PCS_SOCK_F_THROTTLE)
						continue;
					sio_abort(sio, PCS_ERR_NOMEM);
					return;
				}
				sio->read_offset = sio->hdr_ptr;
				sio->hdr_ptr = 0;
				if (sio->flags & PCS_SOCK_F_DYNAMIC_SIZE) {
					msg->done(msg);
					if (++count >= PCS_SIO_PREEMPT_LIMIT)
						return;
					continue;
				}
				sio->current_msg = msg;
			} else {
				if (n < 0) {
					if (errno_eagain(pcs_sock_errno()))
						return;
				}
				if (n == 0 && (sio->flags & PCS_SOCK_F_DYNAMIC_SIZE)) {
					sio->flags |= PCS_SOCK_F_EOF;
					if (sio->netio.eof)
						sio->netio.eof(&sio->netio);
					conn->next_mask &= ~POLLIN;
					break;
				}
				sio_abort(sio, PCS_ERR_NET_ABORT);
				return;
			}
		} else {
			msg = sio->current_msg;

			while (sio->read_offset < msg->size) {
				void * buf;
				int copy;
				int offset = sio->read_offset;

				if (sio->splice_rbuf == NULL) {
					buf = msg->get_chunk(msg, offset, &copy);
					unwind_mr_buf(&buf, &copy);
					if (copy == -1)
						sio->splice_rbuf = pcs_splice_buf_get(buf);
					else if (copy > msg->size - offset)
						copy = msg->size - offset;
				}

				if (sio->splice_rbuf) {
					copy = msg->size - offset;
					n = pcs_splice_buf_recv(sio->splice_rbuf, conn->fd, copy);
					if (n < 0)
						errno = -n;
				} else {
					n = recv(conn->fd, buf, copy, MSG_DONTWAIT);
				}
				if (n > 0) {
					sio->read_offset = offset + n;
				} else {
					if (n < 0 && errno_eagain(pcs_sock_errno()))
						return;
					sio_abort(sio, PCS_ERR_NET_ABORT);
					return;
				}
			}
			sio->current_msg = NULL;
			if (sio->splice_rbuf) {
				pcs_splice_buf_put(sio->splice_rbuf);
				sio->splice_rbuf = NULL;
			}

			msg->done(msg);

			if (++count >= PCS_SIO_PREEMPT_LIMIT)
				return;
		}
	}
}

static void write_space(struct pcs_ioconn * conn)
{
	struct pcs_sockio * sio = sio_from_ioconn(conn);
	int done = 0;
	int count = 0;
	struct pcs_msg * msg;

	conn->next_mask &= ~POLLOUT;

	while (!cd_list_empty(&sio->write_queue)) {
		msg = cd_list_first_entry(&sio->write_queue, struct pcs_msg, list);

		if (pcs_if_error(&sio->error)) {
			pcs_set_local_error(&msg->error, PCS_ERR_NET_ABORT);
			goto done;
		}

		if (count >= PCS_SIO_PREEMPT_LIMIT) {
			conn->next_mask |= POLLOUT;
			break;
		}

		while (sio->write_offset < msg->size) {
			void * buf = NULL;
			int copy;
			int n;
			int offset = sio->write_offset;

			if (sio->splice_wbuf == NULL) {
				buf = msg->get_chunk(msg, offset, &copy);
				unwind_mr_buf(&buf, &copy);

				if (copy == -1) {
					BUG_ON(buf == NULL);
					sio->splice_wbuf = buf;
					copy = pcs_splice_buf_bytes(sio->splice_wbuf);
				}
			} else
				copy = pcs_splice_buf_bytes(sio->splice_wbuf);

			if (copy > msg->size - offset)
				copy = msg->size - offset;

			if (sio->splice_wbuf) {
				n = pcs_splice_buf_send(conn->fd, sio->splice_wbuf, copy);
				if (pcs_splice_buf_bytes(sio->splice_wbuf) == 0) {
					pcs_splice_buf_put(sio->splice_wbuf);
					sio->splice_wbuf = NULL;
				}
				if (n < 0)
					errno = -n;
			} else
				n = send(conn->fd, buf, copy, MSG_DONTWAIT);
			if (n > 0) {
				sio->write_offset = offset + n;
				done = 1;
			} else {
				if (n == 0)
					BUG();

				if (errno_eagain(pcs_sock_errno())) {
					long timeout;
					conn->next_mask |= POLLOUT;

					timeout = (long)(msg->start_time + sio->send_timeout - get_abs_time_fast_ms());
					if (timeout <= 0)
						sio_abort(sio, PCS_ERR_WRITE_TIMEOUT);
					else
						mod_timer(&sio->write_timer, timeout);
					return;
				}
				sio_abort(sio, PCS_ERR_NET_ABORT);
				return;
			}
		}
done:
		cd_list_del(&msg->list);
		if (sio->splice_wbuf) {
			pcs_splice_buf_put(sio->splice_wbuf);
			sio->splice_wbuf = NULL;
		}
		if ((sio->write_queue_len -= msg->size) == 0) {
			if (sio->write_wakeup)
				sio->write_wakeup(sio);
		}
		sio->write_offset = 0;
		pcs_msg_sent(msg);
		msg->done(msg);
		count++;
	}

	del_timer_sync(&sio->write_timer);

	if (done)
		sio_push(sio);
}

void pcs_sock_sendmsg(struct pcs_sockio * sio, struct pcs_msg *msg)
{
	int was_idle = cd_list_empty(&sio->write_queue);

	msg->netio = &sio->netio;

	cd_list_add_tail(&msg->list, &sio->write_queue);
	sio->write_queue_len += msg->size;
	msg->start_time = get_abs_time_fast_ms();
	msg->stage = PCS_MSG_STAGE_SEND;

	if (was_idle) {
		mod_timer(&sio->write_timer, sio->send_timeout);
		write_space(&sio->netio.ioconn);
		pcs_ioconn_schedule(&sio->netio.ioconn);
	}
}

/* Try to cancel message send. If it is impossible, because message is in the middle
 * of write, so nothing and return an error.
 */
int pcs_sock_cancel_msg(struct pcs_msg * msg)
{
	struct pcs_sockio * sio = sio_from_netio(msg->netio);

	BUG_ON(msg->netio == NULL);

	if (sio->write_offset && sio->write_queue.next == &msg->list)
		return -EBUSY;

	cd_list_del(&msg->list);
	if (cd_list_empty(&sio->write_queue))
		del_timer_sync(&sio->write_timer);
	if ((sio->write_queue_len -= msg->size) == 0) {
		if (sio->write_wakeup)
			sio->write_wakeup(sio);
	}
	msg->stage = PCS_MSG_STAGE_SENT;
	return 0;
}

int pcs_sock_queuelen(struct pcs_sockio * sio)
{
	return sio->write_queue_len;
}

static void write_timeout(void * arg)
{
	struct pcs_sockio * sio = arg;

	sio_abort(sio, PCS_ERR_WRITE_TIMEOUT);
}

void pcs_sock_ioconn_destruct(struct pcs_ioconn *ioconn)
{
	struct pcs_sockio * sio = sio_from_ioconn(ioconn);

	BUG_ON(sio->current_msg);
	BUG_ON(!cd_list_empty(&sio->write_queue));
	BUG_ON(sio->write_queue_len);
	BUG_ON(timer_pending(&sio->write_timer));

	ioconn->proc->sio_count--;

	pcs_ioconn_close(ioconn);

	memset(sio, 0xFF, sizeof(*sio));
	pcs_free(sio);
}

static void sio_abort_io(struct pcs_netio *netio, int error)
{
       struct pcs_sockio *sio = sio_from_netio(netio);
       netio->parent = NULL;
       pcs_sock_error(sio, error);
}

static void sio_setup_buffers(struct pcs_netio *netio, int tcp_sndbuf, int tcp_rcvbuf, int local_sndbuf)
{
	struct pcs_sockio *sio = sio_from_netio(netio);

	if (sio->flags & PCS_SOCK_F_CORK)
		pcs_sock_setup_buffers(sio_sock(sio), tcp_sndbuf, tcp_rcvbuf);
	else
		pcs_sock_setup_buffers(sio_sock(sio), local_sndbuf, 0);
}

static unsigned int sio_get_retrans_stat(struct pcs_netio *netio)
{
	unsigned int retrans = 0;
#ifdef HAVE_TCP_INFO
	struct pcs_sockio *sio = sio_from_netio(netio);
	struct tcp_info info;
	socklen_t ilen = sizeof(info);

	BUG_ON(sio == NULL);

	if (getsockopt(netio->ioconn.fd, SOL_TCP, TCP_INFO, &info,  &ilen) == 0) {
		retrans = info.tcpi_total_retrans - sio->retrans;
		sio->retrans = info.tcpi_total_retrans;
	}
#endif
	return retrans;
}

static void sio_trace_health(struct pcs_netio *netio, const char *role, unsigned long long id_val)
{
#ifdef HAVE_TCP_INFO
	struct tcp_info info;
	socklen_t ilen = sizeof(info);
	int fd = netio->ioconn.fd;

	if (getsockopt(fd, SOL_TCP, TCP_INFO, &info,  &ilen) == 0) {
		unsigned int win, sndbuf, rcvbuf, outq;

		ilen = sizeof(win);
		getsockopt(fd, SOL_TCP, TCP_WINDOW_CLAMP, &win, &ilen);
		ilen = sizeof(rcvbuf);
		getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &ilen);
		ilen = sizeof(sndbuf);
		getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &ilen);
		ioctl(fd, TIOCOUTQ, &outq);

		TRACE("Trouble on %s#%llu st=%u/%u bufs=%u/%u/%u/%u queue=%u/%u/%u/%u/%u retr=%u/%u/%u:%u rtt=%u/%u/%u cwnd=%u/%u/%u",
		      role, id_val,
		      info.tcpi_state, info.tcpi_ca_state,
		      rcvbuf, win, sndbuf, outq,
		      info.tcpi_unacked, info.tcpi_sacked, info.tcpi_lost, info.tcpi_retrans, info.tcpi_reordering,
		      info.tcpi_total_retrans, info.tcpi_retransmits, info.tcpi_probes, info.tcpi_backoff,
		      info.tcpi_rtt, info.tcpi_rttvar, info.tcpi_rcv_rtt,
		      info.tcpi_snd_cwnd, info.tcpi_snd_ssthresh, info.tcpi_rcv_space
		      );
	}
#endif
}

static int sio_getmyname(struct pcs_netio *netio, PCS_NET_ADDR_T * addr)
{
	return pcs_sock_getsockname(netio->ioconn.fd, addr);
}

static int sio_getpeername(struct pcs_netio *netio, PCS_NET_ADDR_T * addr)
{
	return pcs_sock_getpeername(netio->ioconn.fd, addr);
}

struct pcs_sockio *
pcs_sockio_fdinit(struct pcs_process * proc, pcs_sock_t fd, int alloc_max, int hdr_max)
{
	struct pcs_sockio * sio;
	struct pcs_ioconn *conn;

	sio = pcs_malloc(sizeof(struct pcs_sockio) + alloc_max);
	if (!sio)
		return NULL;

	proc->sio_count++;

	cd_list_init(&sio->write_queue);
	sio->write_queue_len = 0;

	sio->current_msg = NULL;
	sio->read_offset = 0;
	sio->write_offset = 0;
	sio->splice_wbuf = NULL;
	sio->splice_rbuf = NULL;
	sio->hdr_max = hdr_max;
	sio->hdr_ptr = 0;
	sio->flags = 0;
	sio->retrans = 0;
	sio->msg_count = 0;

	init_timer(proc, &sio->write_timer, write_timeout, sio);
	sio->send_timeout = PCS_SIO_TIMEOUT;

	pcs_sock_nonblock(fd);
	pcs_sock_keepalive(fd);
	if (!pcs_sock_cork(fd))
		sio->flags |= PCS_SOCK_F_CORK;
	else
		pcs_sock_nodelay(fd);

	conn = &sio->netio.ioconn;

	pcs_ioconn_init(proc, conn);
	conn->fd = fd;
	conn->destruct = pcs_sock_ioconn_destruct;
	conn->data_ready = data_ready;
	conn->write_space = write_space;
	conn->error_report = error_report;
	conn->next_mask = POLLIN | POLLRDHUP;
	pcs_clear_error(&sio->error);
	sio->write_wakeup = NULL;

	/* methods */
	sio->netio.tops = &netio_tops;

	return sio;
}

void pcs_sockio_start(struct pcs_sockio * sio)
{
	pcs_ioconn_register(&sio->netio.ioconn);
}

static void pcs_deaccount_msg(struct pcs_msg * msg)
{
	struct pcs_sockio *sio = sio_from_netio(msg->netio);

	sio->netio.ioconn.proc->msg_count--;
	sio->msg_count--;
	msg->netio = NULL;
	if (pcs_if_error(&sio->error) && sio->msg_count == 0)
		pcs_ioconn_unregister(&sio->netio.ioconn);
}

static void pcs_account_msg(struct pcs_sockio * sio, struct pcs_msg * msg)
{
	msg->netio = &sio->netio;
	sio->msg_count++;
	sio->netio.ioconn.proc->msg_count++;
}

static void pcs_msg_input_destructor(struct pcs_msg * msg)
{
	pcs_deaccount_msg(msg);
#ifdef DEBUG
	memset(msg, 0xFF, sizeof(*msg));
#endif
	pcs_free(msg);
}

/* get_chunk() handler for messages with embedded payload right after pcs_msg */
void * pcs_get_chunk_inline(struct pcs_msg * msg, int offset, int *len)
{
	BUG_ON(offset >= msg->size);

	*len = msg->size - offset;
	return msg->_inline_buffer + offset;
}

struct pcs_msg * pcs_alloc_input_msg(struct pcs_sockio * sio, int datalen)
{
	struct pcs_msg * msg;

	msg = pcs_malloc(sizeof(struct pcs_msg) + datalen);
	if (msg) {
		pcs_msg_io_init(msg);
		pcs_account_msg(sio, msg);
		msg->destructor = pcs_msg_input_destructor;
		msg->get_chunk = pcs_get_chunk_inline;
	}
	return msg;
}

static void pcs_io_msg_output_destructor(struct pcs_msg * msg)
{
	BUG_ON(msg->rpc);
#ifdef DEBUG
	memset(msg, 0xFF, sizeof(*msg));
#endif
	pcs_free(msg);
}


struct pcs_msg * pcs_alloc_output_msg(int datalen)
{
	struct pcs_msg * msg;

	msg = pcs_malloc(sizeof(struct pcs_msg) + datalen);
	if (msg) {
		pcs_msg_io_init(msg);
		msg->rpc = NULL;
		msg->netio = NULL;
		msg->destructor = pcs_io_msg_output_destructor;
		msg->get_chunk = pcs_get_chunk_inline;
	}
	return msg;
}

void pcs_free_msg(struct pcs_msg * msg)
{
	pcs_msg_io_fini(msg);

	if (msg->destructor)
		msg->destructor(msg);
}

/* get_chunk() handler for cloned messages */
static void * get_chunk_clone(struct pcs_msg * msg, int offset, int *len)
{
	struct pcs_msg * parent = msg->private;

	BUG_ON(offset >= msg->size);

	return parent->get_chunk(parent, offset, len);
}

void pcs_clone_done(struct pcs_msg * msg)
{
	struct pcs_msg * parent = msg->private;

	pcs_copy_error_cond(&parent->error, &msg->error);

	pcs_msg_io_end(parent);

	pcs_free_msg(msg);
}

struct pcs_msg * pcs_clone_msg(struct pcs_msg * msg)
{
	struct pcs_msg * clone;

	clone = pcs_malloc(sizeof(struct pcs_msg));
	if (clone) {
		pcs_msg_io_init(clone);
		clone->rpc = NULL;
		clone->size = msg->size;
		clone->timeout = 0;
		clone->done = pcs_clone_done;
		clone->destructor = pcs_io_msg_output_destructor;
		clone->private = msg;
		clone->get_chunk = get_chunk_clone;
	}
	return clone;
}

/* get_chunk() handler for cloned messages */
static void * get_chunk_cow_clone(struct pcs_msg * msg, int offset, int *len)
{
	struct pcs_msg * parent = msg->private;

	BUG_ON(offset >= msg->size);

	if (offset < msg->_inline_len) {
		*len = msg->_inline_len - offset;
		return msg->_inline_buffer + offset;
	} else {
		return parent->get_chunk(parent, offset, len);
	}
}

struct pcs_msg * pcs_cow_msg(struct pcs_msg * msg, int copy_len)
{
	struct pcs_msg * clone;

	clone = pcs_malloc(sizeof(struct pcs_msg) + copy_len);
	if (clone) {
		pcs_msg_io_init(clone);
		clone->rpc = NULL;
		clone->size = msg->size;
		clone->timeout = 0;
		clone->done = pcs_clone_done;
		clone->destructor = pcs_io_msg_output_destructor;
		clone->private = msg;
		BUG_ON(copy_len > SHRT_MAX);
		clone->_inline_len = (short)copy_len;
		memcpy(clone->_inline_buffer, msg_inline_head(msg), copy_len);
		clone->get_chunk = get_chunk_cow_clone;
	}
	return clone;
}

void pcs_sock_throttle(struct pcs_sockio * sio)
{
	if ((sio->flags & PCS_SOCK_F_THROTTLE) || pcs_if_error(&sio->error))
		return;

	DTRACE("Throttle on socket %p rpc=%p", sio, sio->netio.parent);
	sio->flags |= PCS_SOCK_F_THROTTLE;
}

void pcs_sock_unthrottle(struct pcs_sockio * sio)
{
	if (!(sio->flags & PCS_SOCK_F_THROTTLE) || pcs_if_error(&sio->error))
		return;

	DTRACE("Unthrottle on socket %p rpc=%p", sio, sio->netio.parent);
	sio->flags &= ~PCS_SOCK_F_THROTTLE;
	if ((sio->flags & PCS_SOCK_F_EOF))
		return;

	sio->netio.ioconn.next_mask |= POLLIN;
	pcs_ioconn_schedule(&sio->netio.ioconn);
}


struct bqmsg
{
	struct bufqueue *bq;
	int last_offset;
};

static void* bqmsg_get_chunk(struct pcs_msg *msg, int offset, int *len)
{
	struct bqmsg *bqmsg = (struct bqmsg *)msg->_inline_buffer;

	BUG_ON(offset < bqmsg->last_offset);
	BUG_ON(offset > msg->size);

	if (offset > bqmsg->last_offset) {
		u32 step = offset - bqmsg->last_offset;
		bufqueue_drain(bqmsg->bq, step);

		bqmsg->last_offset = offset;
	}

	void *buf;
	int s = (int)bufqueue_peek(bqmsg->bq, &buf);
	if ((offset + s) > msg->size)
		s = msg->size - offset;

	BUG_ON(s == 0);

	(*len) = s;
	return buf;
}

static void bqmsg_done(struct pcs_msg *msg)
{
	struct bqmsg *bqmsg = (struct bqmsg *)msg->_inline_buffer;

	BUG_ON(bqmsg->last_offset > msg->size);

	bufqueue_drain(bqmsg->bq, msg->size - bqmsg->last_offset);
	pcs_free_msg(msg);
}

struct pcs_msg* bufqueue_as_pcs_output_msg(struct bufqueue *bq, u32 size)
{
	BUG_ON(size == 0);

	struct pcs_msg *msg = pcs_alloc_output_msg(sizeof(struct bqmsg));
	CHECK_ALLOC(msg);

	msg->timeout = 0;
	msg->size = size;
	msg->get_chunk = &bqmsg_get_chunk;
	msg->done = &bqmsg_done;

	struct bqmsg *bqmsg = (struct bqmsg *)msg->_inline_buffer;
	bqmsg->bq = bq;
	bqmsg->last_offset = 0;

	return msg;
}

/* netio transport operations */

static void sio_register(struct pcs_netio *netio)
{
	pcs_ioconn_register(&netio->ioconn);
}

static void sio_throttle(struct pcs_netio *netio)
{
	pcs_sock_throttle(sio_from_netio(netio));
}

static void sio_unthrottle(struct pcs_netio *netio)
{
	pcs_sock_unthrottle(sio_from_netio(netio));
}

static void sio_sendmsg(struct pcs_netio *netio, struct pcs_msg *msg)
{
	pcs_sock_sendmsg(sio_from_netio(netio), msg);
}

static int sio_cancelmsg(struct pcs_msg *msg)
{
	return pcs_sock_cancel_msg(msg);
}

static struct pcs_netio_tops netio_tops = {
	.register_io	= sio_register,
	.throttle	= sio_throttle,
	.unthrottle	= sio_unthrottle,
	.send_msg	= sio_sendmsg,
	.cancel_msg	= sio_cancelmsg,
	.abort_io	= sio_abort_io,
	.setup_buffers	= sio_setup_buffers,
	.trace_health	= sio_trace_health,
	.getmyname	= sio_getmyname,
	.getpeername	= sio_getpeername,
	.get_retrans_stat = sio_get_retrans_stat,
};
