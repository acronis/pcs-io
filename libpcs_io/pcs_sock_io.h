/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_SOCK_IO_H_
#define _PCS_SOCK_IO_H_ 1

#include "pcs_types.h"
#include "pcs_sock.h"
#include "pcs_process.h"
#include "pcs_error.h"
#include "pcs_net.h"
#include "bug.h"

#define PCS_MSG_MAX_CALENDAR 64
#define PCS_SIO_TIMEOUT	(60*1000)

#define PCS_SIO_PREEMPT_LIMIT	16

struct pcs_msg
{
	struct cd_list	list;

	pcs_error_t	error;
	abs_time_t	start_time;

	void		*private;
	void		*private2;	/* Huh? Need to do something else here. */
	struct pcs_msg	*response;	/* Consider removing. It can be done passing the second
					 * argument to done();
					 */
	struct pcs_netio *netio;
	struct pcs_rpc	*rpc;

	int		size;
	int		_iocount;
	unsigned short	timeout;
	unsigned char	kill_slot;
	unsigned char	stage;
	abs_time_t	io_start_time;

	struct cd_hlist_node	kill_link;

	void *		(*get_chunk)(struct pcs_msg *, int offset, int *len);

	void		(*done)(struct pcs_msg *);
	void		(*destructor)(struct pcs_msg *);
	void		*pool;

	int		accounted;

	short		_align_offset;
	short		_inline_len;

	char 		_inline_buffer[0];
};

static inline void * pcs_msg_aligned_data(struct pcs_msg * msg, int offset)
{
	return (void*)((char *)msg + msg->_align_offset + offset);
}

enum
{
	PCS_MSG_STAGE_NONE	= 0,	/* Initial state */
	PCS_MSG_STAGE_UNSENT	= 1,	/* Message queued somewhere before send */
	PCS_MSG_STAGE_SEND	= 2,	/* Message queued on socket queue */
	PCS_MSG_STAGE_SENT	= 3,	/* Message is sent */
	PCS_MSG_STAGE_WAIT	= 4,	/* Message is waiting for respnose */
	PCS_MSG_STAGE_DONE	= 5,	/* Response received */
};

enum
{
	PCS_SOCK_F_THROTTLE		= 1,
	PCS_SOCK_F_CORK			= 2,
	PCS_SOCK_F_DYNAMIC_SIZE		= 4,
	PCS_SOCK_F_EOF			= 8,
};

struct pcs_sockio
{
	struct pcs_netio	netio;
	u32			msg_count;

	struct cd_list		write_queue;
	int			write_queue_len;

	pcs_error_t		error;

	struct pcs_timer	write_timer;
	int			send_timeout;

	int			hdr_ptr;
	int			hdr_max;
	unsigned int		flags;
	u32			retrans;

	struct pcs_msg		*current_msg;
	int			read_offset;
	int			write_offset;

	struct pcs_splice_buf	*splice_wbuf;
	struct pcs_splice_buf	*splice_rbuf;

	void			(*write_wakeup)(struct pcs_sockio *);

	char			_inline_buffer[0];
};

#define sio_from_netio(nio) container_of(nio, struct pcs_sockio, netio)
#define sio_from_ioconn(conn) container_of(conn, struct pcs_sockio, netio.ioconn)
static inline pcs_sock_t sio_sock(struct pcs_sockio * sio) { return sio->netio.ioconn.fd; }

struct pcs_sockio * pcs_sockio_fdinit(struct pcs_process * proc, pcs_sock_t fd, int alloc_max, int hdr_max);
void pcs_sockio_start(struct pcs_sockio * sio);
void pcs_sock_sendmsg(struct pcs_sockio * sio, struct pcs_msg *msg);
int pcs_sock_cancel_msg(struct pcs_msg * msg);
int pcs_sock_queuelen(struct pcs_sockio * sio);
void pcs_sock_abort(struct pcs_sockio * sio);
void pcs_sock_error(struct pcs_sockio * sio, int error);

void pcs_sock_throttle(struct pcs_sockio * sio);
void pcs_sock_unthrottle(struct pcs_sockio * sio);

struct pcs_msg * pcs_alloc_input_msg(struct pcs_sockio * sio, int datalen);
struct pcs_msg * pcs_alloc_output_msg(int datalen);
struct pcs_msg * pcs_clone_msg(struct pcs_msg * msg);
struct pcs_msg * pcs_cow_msg(struct pcs_msg * msg, int data_len);
void pcs_clone_done(struct pcs_msg * msg);
void pcs_free_msg(struct pcs_msg * msg);
void * pcs_get_chunk_inline(struct pcs_msg * msg, int offset, int *len);
void pcs_msg_sent(struct pcs_msg * msg);

static inline void * msg_inline_head(struct pcs_msg * msg)
{
	int len;

	return msg->get_chunk(msg, 0, &len);
}

static inline void * sio_inline_buffer(struct pcs_sockio * sio)
{
	return sio->_inline_buffer;
}

static inline void pcs_msg_io_init(struct pcs_msg * msg)
{
	pcs_clear_error(&msg->error);
	msg->_iocount = 0;
	msg->done = pcs_free_msg;
}

static inline void pcs_msg_io_start(struct pcs_msg * msg, void (*done)(struct pcs_msg *))
{
	BUG_ON(msg->_iocount != 0);
	msg->_iocount = 1;
	msg->done = done;
}

static inline struct pcs_msg * pcs_msg_io_sched(struct pcs_msg * msg)
{
	BUG_ON(msg->_iocount <= 0);
	msg->_iocount++;
	return msg;
}

static inline void pcs_msg_io_end(struct pcs_msg * msg)
{
	BUG_ON(msg->_iocount <= 0);
	if (--msg->_iocount == 0)
		msg->done(msg);
}

static inline void pcs_msg_io_fini(struct pcs_msg * msg)
{
	BUG_ON(msg->_iocount != 0);
}


struct bufqueue;

/**
   Present a portion of @bq as a pcs_msg that may be passed to pcs_sock_sendmsg().
   Reading data from the pcs_msg will drain @bq.

   \param @bq the buffer queue with the data of a message
   \param @size the length of the head of @bq that will be presented as a pcs_msg
   \returns a pcs_msg that reads data from @bq
*/
struct pcs_msg* bufqueue_as_pcs_output_msg(struct bufqueue *bq, u32 size);

#endif /* _PCS_SOCK_IO_H_ */
