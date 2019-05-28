/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_sock_ssl_priv.h"
#include "pcs_sock_ssl.h"
#include "pcs_co_locks.h"
#include "pcs_malloc.h"
#include "log.h"

#define BUF_TX_LIMIT	(32 * 1024)
#define BUF_RX_LIMIT	(32 * 1024)

#define file2sock(f)	container_of(f, struct pcs_ssl_socket_mt, b.file)

struct pcs_ssl_socket_mt {
	struct pcs_ssl_socket	b;

	struct pcs_co_mutex ssl_mutex;	/* protects SSL state */

	/* network rx/tx queue */
	u8 rx_buf[BUF_RX_LIMIT];		/* net rx: data read from raw socket and awaiting decoding by SSL */
	u8 tx_buf[BUF_TX_LIMIT];		/* net tx: data encoded by SSL and ready to be sent to raw socket */
	int rx_buf_head, rx_buf_tail;
	int tx_buf_head;
	struct pcs_co_mutex rx_mutex, tx_mutex;	/* protects corresponing rx_XXX/tx_XXX vars */
};

static struct pcs_co_file_ops pcs_co_file_ssl_ops;
static int pcs_ssl_socket_co_handshake(struct pcs_ssl_socket *sock_b);

/*================ bio ================*/

static inline struct pcs_ssl_socket_mt *sock_from_bio(BIO *b)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000
	return BIO_get_data(b);
#else
	return b->ptr;
#endif
}

static int do_network_read(struct pcs_ssl_socket_mt *sock);
static int do_network_write(struct pcs_ssl_socket_mt *sock);

static int pcs_bio_read(BIO *b, char *buf, int len)
{
	struct pcs_ssl_socket_mt *sock = sock_from_bio(b);

	if (!pcs_co_mutex_trylock(&sock->rx_mutex)) {
		int sz = sock->rx_buf_head - sock->rx_buf_tail;
		if (sz > len)
			sz = len;
		if (sz) {
			memcpy(buf, sock->rx_buf + sock->rx_buf_tail, sz);
			sock->rx_buf_tail += sz;
			pcs_co_mutex_unlock(&sock->rx_mutex);
			BIO_clear_retry_flags(b);
			return sz;
		}
		pcs_co_mutex_unlock(&sock->rx_mutex);
	}

	BIO_set_retry_read(b);
	return -1;
}

static int pcs_bio_write(BIO *b, const char *buf, int len)
{
	struct pcs_ssl_socket_mt *sock = sock_from_bio(b);

	if (!pcs_co_mutex_trylock(&sock->tx_mutex)) {
		int sz = BUF_TX_LIMIT - sock->tx_buf_head;
		if (sz > len)
			sz = len;
		if (sz) {
			memcpy(sock->tx_buf + sock->tx_buf_head, buf, sz);
			sock->tx_buf_head += sz;
			pcs_co_mutex_unlock(&sock->tx_mutex);
			BIO_clear_retry_flags(b);
			return sz;
		}
		pcs_co_mutex_unlock(&sock->tx_mutex);
	}

	BIO_set_retry_write(b);
	return -1;
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

static BIO* make_bio(struct pcs_ssl_socket_mt *sock)
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

struct pcs_co_file* pcs_ssl_socket_mt(struct pcs_co_file *raw_socket)
{
	struct pcs_ssl_socket_mt *sock = pcs_xzmalloc(sizeof(*sock));

	pcs_ssl_socket_init(&sock->b);

	sock->b.raw_sock = raw_socket;

	pcs_co_mutex_init(&sock->ssl_mutex);
	pcs_co_mutex_init(&sock->rx_mutex);
	pcs_co_mutex_init(&sock->tx_mutex);

	pcs_co_file_init(&sock->b.file, &pcs_co_file_ssl_ops);
	sock->b.handshake = pcs_ssl_socket_co_handshake;

	return &sock->b.file;
}

static void pcs_ssl_socket_free(struct pcs_ssl_socket_mt *sock)
{
	pcs_ssl_socket_fini(&sock->b);

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

static int do_network_read(struct pcs_ssl_socket_mt *sock)
{
	pcs_co_mutex_lock(&sock->rx_mutex);

	/* can race with bio_read or another SSL op already requested the data via WANT_READ */
	int sz = sock->rx_buf_tail < sock->rx_buf_head;
	if (sz) {
		pcs_co_mutex_unlock(&sock->rx_mutex);
		return sz;
	}

	sz = pcs_co_file_read_ex(sock->b.raw_sock, sock->rx_buf, BUF_RX_LIMIT, CO_IO_PARTIAL);
	if (sz > 0) {
		sock->rx_buf_tail = 0;
		sock->rx_buf_head = sz;
	}

	pcs_co_mutex_unlock(&sock->rx_mutex);
	return sz;
}

/* returns <0 error, =0 nothing done, >0 smth was written */
static int do_network_write(struct pcs_ssl_socket_mt *sock)
{
	pcs_co_mutex_lock(&sock->tx_mutex);

	if (!sock->tx_buf_head) {
		pcs_co_mutex_unlock(&sock->tx_mutex);
		return 0;
	}

	int sz = pcs_co_file_write_ex(sock->b.raw_sock, sock->tx_buf, sock->tx_buf_head, 0);
	if (sz < 0) {
		pcs_co_mutex_unlock(&sock->tx_mutex);
		return sz;
	}

	BUG_ON(sz != sock->tx_buf_head);
	sock->tx_buf_head = 0;

	pcs_co_mutex_unlock(&sock->tx_mutex);
	pcs_sock_push(pcs_co_file_sock(sock->b.raw_sock));
	return sz;
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

static int pcs_ssl_socket_op_locked(struct pcs_ssl_socket_mt *sock, struct io_op *op)
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

	if (err > 0) {
		err = 0;
		op->ssl_err = 0;
	} else if (err <= 0) {
		err = SSL_get_error(sock->b.ssl, err);
		op->ssl_err = ERR_get_error();
		ERR_clear_error();
	}

	return err;
}

static int pcs_ssl_socket_op_co(struct pcs_ssl_socket_mt *sock, struct io_op *op)
{
	op->total = 0;
	op->sys_err = 0;
	while (op->size > 0) {
		pcs_co_mutex_lock(&sock->ssl_mutex);
		int ssl_rc = pcs_ssl_socket_op_locked(sock, op);
		pcs_co_mutex_unlock(&sock->ssl_mutex);

		if ((op->code == OP_READ || op->code ==OP_READV) && ssl_rc == SSL_ERROR_ZERO_RETURN)
			break;
		/* we read min_size requested, further reads will block */
		if ((op->code == OP_READ || op->code ==OP_READV) && op->total >= op->min_size && ssl_rc == SSL_ERROR_WANT_READ)
			break;

		/* TODO minor: when there is smth in tx_bq, but SSL didn't ask for WANT_WRITE, then we'd better
		 * perform async writes from special writer co. I think this is minor however */
		int io_rc = do_network_write(sock);
		if (io_rc < 0) {
			save_last_os_error_string(&sock->b, io_rc);
			op->sys_err = io_rc;
			return -pcs_errno_to_err(-io_rc);
		}

		if (!ssl_rc || ssl_rc == SSL_ERROR_WANT_WRITE)
			continue;

		if (ssl_rc == SSL_ERROR_WANT_READ) {
			io_rc = do_network_read(sock);
			if (io_rc < 0) {
				save_last_os_error_string(&sock->b, io_rc);
				op->sys_err = io_rc;
				return -pcs_errno_to_err(-io_rc);
			}

			if (io_rc > 0)		/* did some I/O, restart */
				continue;
		}

		save_last_ssl_error_string(&sock->b, op->ssl_err);
		op->sys_err = -PCS_ESSL;
		return -ssl_op_error(op);
	}
	return op->total;
}

static int pcs_ssl_socket_co_handshake(struct pcs_ssl_socket *sock_b)
{
	struct pcs_ssl_socket_mt *sock = container_of(sock_b, struct pcs_ssl_socket_mt, b);
	BUG_ON(sock->b.state != SOCKSTATE_CONNECTING && sock->b.state != SOCKSTATE_ACCEPTING);

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
	struct pcs_ssl_socket_mt *sock = file2sock(file);

	if (flags & CO_IO_NOWAIT)
		return 0;

	u32 need_min = (flags & CO_IO_PARTIAL) ? 1 : size;

	struct io_op op = {
		.code = OP_READ,
		.buf = buf,
		.size = need_min,
		.min_size = need_min,
		.total = 0
	};
	int rc = pcs_ssl_socket_op_co(sock, &op);
	if (rc < 0)
		return op.sys_err;

	return op.total;
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
	struct pcs_ssl_socket_mt *sock = file2sock(file);

	if (flags & CO_IO_NOWAIT)
		return 0;

	u32 need_min = (flags & CO_IO_PARTIAL) ? 1 : iov_size(iovcnt, iov);

	struct io_op op = {
		.code = OP_READV,
		.iovcnt = iovcnt,
		.iov = iov,
		.size = need_min,
		.min_size = need_min,
		.total = 0
	};
	int rc = pcs_ssl_socket_op_co(sock, &op);
	if (rc < 0)
		return op.sys_err;

	return op.total;
}

static int pcs_ssl_socket_co_write(struct pcs_co_file *file, const void * buf, int size, u64 offset, u32 flags)
{
	BUG_ON(flags != 0); /* unsupported */
	struct pcs_ssl_socket_mt *sock = file2sock(file);

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
	struct pcs_ssl_socket_mt *sock = file2sock(file);

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
	struct pcs_ssl_socket_mt *sock = file2sock(file);

	if (sock->b.state != SOCKSTATE_INIT) {
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
