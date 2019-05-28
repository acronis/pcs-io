/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_sock_ssl_priv.h"
#include "pcs_sock_ssl.h"
#include "pcs_co_locks.h"
#include "pcs_context.h"
#include "pcs_malloc.h"
#include "bufqueue.h"
#include "log.h"

#define BUF_TX_LIMIT	(128 * 1024)
#define BUF_RX_LIMIT	(12 * 1024)
#define BUF_U_RX_LIMIT	(64 * 1024)

#define file2sock(f)	container_of(f, struct pcs_ssl_socket_st, b.file)

struct pcs_ssl_socket_st {
	struct pcs_ssl_socket	b;

	pthread_mutex_t ssl_mutex;	/* protects SSL state */

	/* network rx/tx queue */
	struct pcs_co_mutex tx_co_mutex, rx_co_mutex;
	struct bufqueue tx_bq;			/* net tx: data encoded by SSL and ready to be sent to raw socket */
	struct bufqueue u_rx_bq;		/* user rx: data decoded by SSL and ready to be read by user */
	int rx_shutdown, tx_shutdown;
	pthread_mutex_t rx_mutex, tx_mutex;	/* protects corresponing rx_XXX/tx_XXX vars */
	int tx_need_push;

	u16 offload_job_hash;

	u32 u_rx_size_limit;
	u32 tx_size_limit;

	char rx_buf[BUF_RX_LIMIT];	/* small temp buffer for rx to avoid frequent large allocations as we rarely see > 12KB reads in production */
	u32 rx_buf_head, rx_buf_tail;	/* [head, tail) indicates which portion of rx_buf is filled */
};

static struct pcs_co_file_ops pcs_co_file_ssl_ops;
static int pcs_ssl_socket_co_handshake(struct pcs_ssl_socket *sock_b);

/*================ bio ================*/

static inline struct pcs_ssl_socket_st *sock_from_bio(BIO *b)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000
	return BIO_get_data(b);
#else
	return b->ptr;
#endif
}

static int do_network_read(struct pcs_ssl_socket_st *sock, int ioflags);
static int do_network_write(struct pcs_ssl_socket_st *sock, int ioflags);

static int pcs_bio_read(BIO *b, char *buf, int _len)
{
	struct pcs_ssl_socket_st *sock = sock_from_bio(b);
	u32 len = (u32)_len, sz = 0;

	if (pthread_mutex_trylock(&sock->rx_mutex))
		goto out;

	if (sock->rx_buf_tail != sock->rx_buf_head) {
		BUG_ON(sock->rx_buf_head > sock->rx_buf_tail);

		sz = sock->rx_buf_tail - sock->rx_buf_head;
		if (sz > len)
			sz = len;

		memcpy(buf, &sock->rx_buf[sock->rx_buf_head], sz);
		sock->rx_buf_head += sz;
		if (sock->rx_buf_head == sock->rx_buf_tail)
			sock->rx_buf_head = sock->rx_buf_tail = 0;

		goto out_unlock;
	}

	if (sock->rx_shutdown)
		goto out_unlock;

	struct iovec iov[2] = {
		{buf, len},
		{&sock->rx_buf[0], sizeof(sock->rx_buf)}
	};

	int ret = pcs_co_file_readv_ex(sock->b.raw_sock, 2, iov, CO_IO_NOWAIT);
	if (ret > len) {
		BUG_ON(sock->rx_buf_head != 0 || sock->rx_buf_tail != 0);

		sock->rx_buf_tail = ret - len;
		sz = len;
	} else if (ret >= 0) {
		sz = ret;
	}

out_unlock:
	pthread_mutex_unlock(&sock->rx_mutex);
out:
	if (!sz) {
		BIO_set_retry_read(b);
		return (-1);
	} else {
		BIO_clear_retry_flags(b);
		return sz;
	}
}

static int pcs_bio_write(BIO *b, const char *buf, int len)
{
	struct pcs_ssl_socket_st *sock = sock_from_bio(b);
	u32 written = 0;

	if (pthread_mutex_trylock(&sock->tx_mutex))
		goto done;

	u32 bqsz = bufqueue_get_size(&sock->tx_bq);
	if (bqsz >= sock->tx_size_limit)
		goto unlock;
	if (sock->tx_shutdown)
		goto unlock;

	if (bufqueue_empty(&sock->tx_bq)) {
		int r = pcs_co_file_write_ex(sock->b.raw_sock, buf, len, CO_IO_NOWAIT);
		if (r < 0) {
			sock->tx_shutdown = r;
			goto unlock;
		} else if (r > 0) {
			written += r;
			buf += r;
			len -= r;
			sock->tx_need_push = 1;
		}
	}

	bufqueue_put_copy(&sock->tx_bq, buf, len);
	written += len;

unlock:
	pthread_mutex_unlock(&sock->tx_mutex);

done:
	if (!written) {
		BIO_set_retry_write(b);
		return (-1);
	} else {
		BIO_clear_retry_flags(b);
		return written;
	}
}

static long pcs_bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	switch (cmd) {
	case BIO_CTRL_PUSH:
	case BIO_CTRL_POP:
		/* these may be ignored, see crypto/bio/bss_{file,mem}.c */
		return 1;

	case BIO_CTRL_FLUSH:
		return 1;

	default:
		pcs_fatal("not implemented: bq_ctrl(cmd = %i, num = %li)", cmd, num);
	}
}

static int pcs_bio_destroy(BIO *b)
{
	return 1;
}

static BIO_METHOD *sslsock_bio_method(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000
	static BIO_METHOD *biom = NULL;
	if (!biom) {
		biom = BIO_meth_new(BIO_TYPE_SOCKET, "sslsock bio");
		CHECK_ALLOC(biom);

		BIO_meth_set_write(biom, pcs_bio_write);
		BIO_meth_set_read(biom, pcs_bio_read);
		BIO_meth_set_ctrl(biom, pcs_bio_ctrl);
		BIO_meth_set_destroy(biom, pcs_bio_destroy);
	}
	return biom;
#else
	static BIO_METHOD biom = {
		.type		= BIO_TYPE_SOCKET,
		.name		= "sslsock bio",
		.bwrite		= pcs_bio_write,
		.bread		= pcs_bio_read,
		.ctrl		= pcs_bio_ctrl,
		.destroy	= pcs_bio_destroy
	};
	return &biom;
#endif
};

static BIO* make_bio(struct pcs_ssl_socket_st *sock)
{
	BIO *bio = BIO_new(sslsock_bio_method());
	CHECK_ALLOC(bio);

#if OPENSSL_VERSION_NUMBER >= 0x10100000
	BIO_set_data(bio, sock);
	BIO_set_shutdown(bio, 0);
	BIO_set_init(bio, 1);
#else
	bio->ptr = sock;
	bio->shutdown = 0;
	bio->init = 1;
#endif

	return bio;
}

/*================ public API ================*/

static u16 next_job_hash;

struct pcs_co_file* pcs_ssl_socket_st(struct pcs_co_file *raw_socket)
{
	struct pcs_ssl_socket_st *sock = pcs_xzmalloc(sizeof(*sock));

	pcs_ssl_socket_init(&sock->b);

	sock->b.raw_sock = raw_socket;

	bufqueue_init(&sock->u_rx_bq);
	sock->u_rx_size_limit = BUF_U_RX_LIMIT;

	sock->rx_buf_head = sock->rx_buf_tail = 0;

	bufqueue_init(&sock->tx_bq);
	sock->tx_size_limit = BUF_TX_LIMIT;
	sock->tx_bq.prealloc_size = BUF_TX_LIMIT / 4;

	pcs_co_mutex_init(&sock->rx_co_mutex);
	pcs_co_mutex_init(&sock->tx_co_mutex);
	pthread_mutex_init(&sock->ssl_mutex, NULL);
	pthread_mutex_init(&sock->rx_mutex, NULL);
	pthread_mutex_init(&sock->tx_mutex, NULL);

	sock->offload_job_hash = next_job_hash++;

	pcs_co_file_init(&sock->b.file, &pcs_co_file_ssl_ops);
	sock->b.handshake = pcs_ssl_socket_co_handshake;

	return &sock->b.file;
}

static void pcs_ssl_socket_free(struct pcs_ssl_socket_st *sock)
{
	pcs_ssl_socket_fini(&sock->b);

	bufqueue_clear(&sock->u_rx_bq);
	bufqueue_clear(&sock->tx_bq);
	pthread_mutex_destroy(&sock->ssl_mutex);
	pthread_mutex_destroy(&sock->rx_mutex);
	pthread_mutex_destroy(&sock->tx_mutex);

	memset(sock, 0x55, sizeof(*sock));
	pcs_free(sock);
}

struct io_op {
#define OP_READ		1
#define OP_READV	2
#define OP_WRITE	3
#define OP_WRITEV	4
#define OP_CONNECT	5
#define OP_ACCEPT	6
#define OP_SHUTDOWN	7
	int code;
	void *buf;
	int iovcnt;
	struct iovec *iov;
	int min_size;	/* min size to read */
	int size;	/* size left in buffer */
	int total;	/* total processed */
	size_t offs;	/* offset from iov entry */
	unsigned long ssl_err;
	int sys_err;	/* system error / errno */
};

/* called under sock->rx_mutex */
static int do_network_read(struct pcs_ssl_socket_st *sock, int ioflags)
{
	if (sock->rx_shutdown)
		return 0;

	/* can race with bio_read or another SSL op already requested the data via WANT_READ */
	if (sock->rx_buf_tail != sock->rx_buf_head)
		return 1;	/* report some progress, actual number of bytes not important */

	int ret = pcs_co_file_read_ex(sock->b.raw_sock, sock->rx_buf, sizeof(sock->rx_buf), ioflags);
	if (ret > 0) {
		BUG_ON(sock->rx_buf_head != 0 || sock->rx_buf_tail != 0);
		sock->rx_buf_tail = ret;
	} else if (ret == 0 && !(ioflags & CO_IO_NOWAIT)) {
		sock->rx_shutdown = 1;
	}

	return ret;
}

/* called under sock->tx_mutex, returns <0 error, =0 nothing done, >0 smth was written */
static int do_network_write(struct pcs_ssl_socket_st *sock, int ioflags)
{
	if (sock->tx_shutdown)	/* NOTE: it's negative error code */
		return sock->tx_shutdown;

	int ret = 0;

	while (!bufqueue_empty(&sock->tx_bq)) {
		struct iovec iov[64];
		int iovcnt = bufqueue_peek_at_iov(&sock->tx_bq, 0, iov, 64, NULL);

		BUG_ON(iovcnt < 1);

		int r = pcs_co_file_writev_ex(sock->b.raw_sock, iovcnt, iov, ioflags);
		if (r < 0) {
			ret = sock->tx_shutdown = r;
			break;
		} else if (r == 0) {
			break;
		} else if (r > 0) {
			bufqueue_drain(&sock->tx_bq, r);
			sock->tx_need_push = 1;
			ret += r;
		}
	}

	return ret;
}

static void ssl_sock_push(struct pcs_ssl_socket_st *sock)
{
	if (!sock->tx_need_push)
		return;

	pcs_sock_push(pcs_co_file_sock(sock->b.raw_sock));
	sock->tx_need_push = 0;
}

static int pcs_ssl_check_io(struct pcs_ssl_socket_st *sock, struct io_op *op, int rc)
{
	int r = 0, w = 0;

	/* TODO minor: when there is smth in tx_bq, but SSL didn't ask for WANT_WRITE, then we'd better
	 * perform async writes from special writer co. I think this is minor however */
	if (rc == SSL_ERROR_WANT_WRITE || !bufqueue_empty_unsafe(&sock->tx_bq)) {
		pcs_co_mutex_lock(&sock->tx_co_mutex);
		pthread_mutex_lock(&sock->tx_mutex);
		w = do_network_write(sock, 0);
		ssl_sock_push(sock);
		pthread_mutex_unlock(&sock->tx_mutex);
		pcs_co_mutex_unlock(&sock->tx_co_mutex);
		if (w < 0)
			return w;

		/* If we have concurrent reads and writes on an ssl socket, then two offload threads
		   may race for do_network_write(), and a loser will get w == 0 here. Thus, always
		   report some IO here to convince pcs_ssl_socket_op_co() into retrying SSL_write()
		   or SSL_read(). */
		w = 1;
	}

	if (rc == SSL_ERROR_WANT_READ) {
		pcs_co_mutex_lock(&sock->rx_co_mutex);
		pthread_mutex_lock(&sock->rx_mutex);
		r = do_network_read(sock, CO_IO_PARTIAL);
		pthread_mutex_unlock(&sock->rx_mutex);
		pcs_co_mutex_unlock(&sock->rx_co_mutex);
		if (r < 0)
			return r;
	}
	return r + w;
}

static int ssl_op_error(struct io_op *op)
{
	switch (ERR_GET_REASON(op->ssl_err)) {
	case SSL_AD_REASON_OFFSET + SSL_AD_CERTIFICATE_EXPIRED: return PCS_ERR_SSL_CERTIFICATE_EXPIRED;
	case SSL_AD_REASON_OFFSET + SSL_AD_CERTIFICATE_REVOKED: return PCS_ERR_SSL_CERTIFICATE_REVOKED;
	case SSL_AD_REASON_OFFSET + SSL_AD_UNKNOWN_CA:          return PCS_ERR_SSL_UNKNOWN_CA;
	default: return PCS_ERR_SSL;
	}
}

static int pcs_ssl_socket_op_thread_locked(struct pcs_ssl_socket_st *sock, struct io_op *op)
{
	int err = 0;

	switch (op->code) {
	case OP_READ:
		while (op->size) {
			err = SSL_read(sock->b.ssl, (char *)op->buf + op->total, op->size);
			if (err <= 0)
				break;

			op->total += err;
			op->size -= err;
		}
		break;
	case OP_READV:
		while (op->iovcnt > 0) {
			if (op->offs >= op->iov->iov_len) {
				BUG_ON(op->offs != op->iov->iov_len);
				op->iov++;
				op->iovcnt--;
				op->offs = 0;
				continue;
			}

			err = SSL_read(sock->b.ssl, (char *)op->iov->iov_base + op->offs, (int)(op->iov->iov_len - op->offs));
			if (err <= 0)
				break;

			op->total += err;
			op->size -= err;
			op->offs += err;
		}
		break;
	case OP_WRITE:
		while (op->size) {
			err = SSL_write(sock->b.ssl, (char *)op->buf + op->total, op->size);
			if (err <= 0)
				break;

			op->total += err;
			op->size -= err;
		}
		break;
	case OP_WRITEV:
		while (op->iovcnt > 0) {
			if (op->offs >= op->iov->iov_len) {
				BUG_ON(op->offs != op->iov->iov_len);
				op->iov++;
				op->iovcnt--;
				op->offs = 0;
				continue;
			}

			err = SSL_write(sock->b.ssl, (char *)op->iov->iov_base + op->offs, (int)(op->iov->iov_len - op->offs));
			if (err <= 0)
				break;

			op->total += err;
			op->size -= err;
			op->offs += err;
		}
		break;
	case OP_CONNECT:
		err = SSL_connect(sock->b.ssl);
		op->size = err > 0 ? 0 : 1;
		op->total = 1 - op->size;	/* 1 done, 0 - not done */
		break;
	case OP_ACCEPT:
		err = SSL_accept(sock->b.ssl);
		op->size = err > 0 ? 0 : 1;
		op->total = 1 - op->size;	/* 1 done, 0 - not done */
		break;
	case OP_SHUTDOWN:
		err = SSL_shutdown(sock->b.ssl);
		op->size = err > 0 ? 0 : 1;
		op->total = 1 - op->size;	/* 1 done, 0 - not done */
		break;
	}

	if ((sock->tx_need_push || !bufqueue_empty(&sock->tx_bq)) && !pthread_mutex_trylock(&sock->tx_mutex)) {
		do_network_write(sock, CO_IO_NOWAIT);
		ssl_sock_push(sock);	/* push everything that was written by operations above + do_network_write */
		pthread_mutex_unlock(&sock->tx_mutex);
	}

	if (err > 0) {
		err = 0;
		op->ssl_err = 0;
	} else if (err <= 0) {
		err = SSL_get_error(sock->b.ssl, err);

		/* save detailed error status also */
		op->ssl_err = ERR_get_error();
		save_last_ssl_error_string(&sock->b, op->ssl_err);
		ERR_clear_error();
	}

	return err;
}

static int pcs_ssl_socket_op_thread(struct pcs_ssl_socket_st *sock, struct io_op *op)
{
	pthread_mutex_lock(&sock->ssl_mutex);
	int res = pcs_ssl_socket_op_thread_locked(sock, op);
	pthread_mutex_unlock(&sock->ssl_mutex);
	return res;
}

static int pcs_ssl_socket_op_co(struct pcs_ssl_socket_st *sock, struct io_op *op)
{
	op->total = 0;
	op->sys_err = 0;
	while (op->size > 0) {
		int io_rc = pcs_co_ctx_is_canceled();
		if (io_rc) {
			op->sys_err = io_rc;
			return -pcs_errno_to_err(-io_rc);
		}

		int ssl_rc;
		if ((op->code == OP_READ || op->code == OP_READV || op->code == OP_WRITE || op->code == OP_WRITEV) && op->size <= 1024 && !pthread_mutex_trylock(&sock->ssl_mutex)) {
			ssl_rc = pcs_ssl_socket_op_thread_locked(sock, op);
			pthread_mutex_unlock(&sock->ssl_mutex);
		} else {
			struct pcs_coroutine *co = pcs_co_migrate_to_thread_hash(pcs_current_proc->co_ssl, sock->offload_job_hash);
			ssl_rc = pcs_ssl_socket_op_thread(sock, op);
			pcs_co_migrate_from_thread(co);
		}

		if ((op->code == OP_READ || op->code == OP_READV) && ssl_rc == SSL_ERROR_ZERO_RETURN)
			break;
		/* we read min_size requested, further reads will block */
		if ((op->code == OP_READ || op->code == OP_READV) && op->total >= op->min_size && ssl_rc == SSL_ERROR_WANT_READ)
			break;

		if (ssl_rc == 0 || ssl_rc == SSL_ERROR_WANT_READ || ssl_rc == SSL_ERROR_WANT_WRITE)
			io_rc = pcs_ssl_check_io(sock, op, ssl_rc);
		if (io_rc > 0)		/* did some I/O, restart */
			continue;
		if (io_rc < 0) {
			save_last_os_error_string(&sock->b, io_rc);
			op->sys_err = io_rc;
			return -pcs_errno_to_err(-io_rc);
		}

		if (ssl_rc == 0)
			continue;

		/* nothing to read, EOF... */
		if (ssl_rc == SSL_ERROR_WANT_READ && sock->rx_shutdown)
			break;
		if (ssl_rc == SSL_ERROR_WANT_WRITE && sock->tx_shutdown)
			break;

		op->sys_err = -PCS_ESSL;
		return -ssl_op_error(op);
	}
	return op->total;
}

static int pcs_ssl_socket_co_handshake(struct pcs_ssl_socket *sock_b)
{
	struct pcs_ssl_socket_st *sock = container_of(sock_b, struct pcs_ssl_socket_st, b);
	BUG_ON(sock->b.state != SOCKSTATE_CONNECTING && sock->b.state != SOCKSTATE_ACCEPTING);
	BUG_ON(!pcs_current_proc->co_ssl);

	SSL_set_bio(sock->b.ssl, make_bio(sock), make_bio(sock));

	struct io_op op = {
		.code = (sock->b.state == SOCKSTATE_CONNECTING ? OP_CONNECT : OP_ACCEPT),
		.buf = NULL,
		.size = 1,
	};

	int err = pcs_ssl_socket_op_co(sock, &op);

	if (err < 0)
		return err;
	if (!err)
		return -PCS_ERR_NET;
	return 0;
}

static int pcs_ssl_socket_co_read(struct pcs_co_file *file, void * buf, int size, u64 offset, u32 flags)
{
	struct pcs_ssl_socket_st *sock = file2sock(file);

	/* prefetch / cache enough data in u_rx_bq */
	u32 bqsz = bufqueue_get_size(&sock->u_rx_bq);
	if (flags & CO_IO_NOWAIT)
		goto nowait;
	if ((flags & CO_IO_PARTIAL) && bqsz > 0)
		goto nowait;
	if (bqsz >= size)
		goto nowait;

	u32 need_min = (flags & CO_IO_PARTIAL) ? 1 : size - bqsz;

	if (need_min > sock->u_rx_size_limit / 2) {
		bufqueue_get_copy(&sock->u_rx_bq, buf, bqsz);

		struct io_op op = {
			.code = OP_READ,
			.buf = (u8 *)buf + bqsz,
			.size = need_min,
			.min_size = need_min,
			.total = 0
		};
		int rc = pcs_ssl_socket_op_co(sock, &op);
		if (rc < 0)
			return op.sys_err;

		return bqsz + op.total;
	} else {
		u32 need_max = need_min + sock->u_rx_size_limit;
		struct io_op op = {
			.code = OP_READ,
			.buf = pcs_xmalloc(need_max),
			.size = need_max,
			.min_size = need_min,
			.total = 0
		};
		int rc = pcs_ssl_socket_op_co(sock, &op);
		if (rc < 0) {
			pcs_free(op.buf);
			return op.sys_err;
		}

		if (op.total > need_max / 2) {
			bufqueue_put(&sock->u_rx_bq, op.buf, op.total);
		} else {
			bufqueue_put_copy(&sock->u_rx_bq, op.buf, op.total);
			pcs_free(op.buf);
		}
	}

nowait:
	return bufqueue_get_copy(&sock->u_rx_bq, buf, size);
}

static u32 iov_size(int iovcnt, struct iovec *iov)
{
	size_t size = 0;
	int i;
	for (i = 0; i < iovcnt; i++)
		size += iov[i].iov_len;
	BUG_ON(size > INT_MAX);
	return (u32)size;
}

static int pcs_ssl_socket_co_readv(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u64 offset, u32 flags)
{
	struct pcs_ssl_socket_st *sock = file2sock(file);

	/* prefetch / cache enough data in u_rx_bq */
	u32 bqsz = bufqueue_get_size(&sock->u_rx_bq);
	if (flags & CO_IO_NOWAIT)
		goto nowait;
	if ((flags & CO_IO_PARTIAL) && bqsz > 0)
		goto nowait;
	u32 size = iov_size(iovcnt, iov);
	if (bqsz >= size)
		goto nowait;

	u32 need_min = (flags & CO_IO_PARTIAL) ? 1 : size - bqsz;

	if (need_min > sock->u_rx_size_limit / 2) {
		u32 n = bufqueue_get_copy_iovec(&sock->u_rx_bq, iovcnt, iov);
		BUG_ON(n != bqsz);

		while (n >= iov->iov_len) {
			n -= (u32)iov->iov_len;
			iov++;
			iovcnt--;
		}

		struct iovec save_iov = *iov;
		iov->iov_base = (char *)iov->iov_base + n;
		iov->iov_len -= n;

		struct io_op op = {
			.code = OP_READV,
			.iovcnt = iovcnt,
			.iov = iov,
			.size = need_min,
			.min_size = need_min,
			.total = 0
		};
		int rc = pcs_ssl_socket_op_co(sock, &op);
		*iov = save_iov;
		if (rc < 0)
			return op.sys_err;

		return bqsz + op.total;
	} else {
		u32 need_max = need_min + sock->u_rx_size_limit;
		struct io_op op = {
			.code = OP_READ,
			.buf = pcs_xmalloc(need_max),
			.size = need_max,
			.min_size = need_min,
			.total = 0
		};
		int rc = pcs_ssl_socket_op_co(sock, &op);
		if (rc < 0) {
			pcs_free(op.buf);
			return op.sys_err;
		}

		if (op.total > need_max / 2) {
			bufqueue_put(&sock->u_rx_bq, op.buf, op.total);
		} else {
			bufqueue_put_copy(&sock->u_rx_bq, op.buf, op.total);
			pcs_free(op.buf);
		}
	}

nowait:
	return bufqueue_get_copy_iovec(&sock->u_rx_bq, iovcnt, iov);
}

static int pcs_ssl_socket_co_write(struct pcs_co_file *file, const void * buf, int size, u64 offset, u32 flags)
{
	BUG_ON(flags != 0); /* unsupported */
	struct pcs_ssl_socket_st *sock = file2sock(file);

	struct io_op op = {
		.code = OP_WRITE,
		.buf = (void *)buf,
		.size = size,
		.total = 0
	};

	int rc = pcs_ssl_socket_op_co(sock, &op);
	return (rc < 0) ? op.sys_err : rc;
}

static int pcs_ssl_socket_co_writev(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u64 offset, u32 flags)
{
	BUG_ON(flags != 0); /* unsupported */
	struct pcs_ssl_socket_st *sock = file2sock(file);

	struct io_op op = {
		.code = OP_WRITEV,
		.iovcnt = iovcnt,
		.iov = iov,
		.size = iov_size(iovcnt, iov),
		.total = 0
	};

	int rc = pcs_ssl_socket_op_co(sock, &op);
	return (rc < 0) ? op.sys_err : rc;
}

static int pcs_ssl_socket_co_close(struct pcs_co_file *file)
{
	struct pcs_ssl_socket_st *sock = file2sock(file);

	if (sock->b.state != SOCKSTATE_INIT && !sock->tx_shutdown) {
		struct io_op op = {
			.code = OP_SHUTDOWN,
			.size = 1
		};

		pcs_ssl_socket_op_co(sock, &op);
	}

	pcs_co_file_close(sock->b.raw_sock);
	pcs_ssl_socket_free(sock);

	return 0;
}

static struct pcs_co_file_ops pcs_co_file_ssl_ops = {
	.read	= pcs_ssl_socket_co_read,
	.write	= pcs_ssl_socket_co_write,
	.readv	= pcs_ssl_socket_co_readv,
	.writev	= pcs_ssl_socket_co_writev,
	.close	= pcs_ssl_socket_co_close,
};
