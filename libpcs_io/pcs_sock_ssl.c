/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#include "pcs_process.h"
#include "pcs_sock_ssl.h"
#include "pcs_sock.h"
#include "pcs_co_locks.h"
#include "pcs_context.h"
#include "bufqueue.h"
#include "pcs_co_io.h"
#include "pcs_malloc.h"
#include "pcs_errno.h"
#include "pcs_error.h"
#include "pcs_thread.h"
#include "log.h"
#include "bug.h"

#define BUF_TX_LIMIT (128*1024)
#define BUF_RX_LIMIT (128*1024)
#define BUF_U_RX_LIMIT (64*1024)

#define file2sock(f) container_of(f, struct pcs_ssl_socket, file)

struct pcs_ssl_socket
{
	struct pcs_co_file file;	/* should be the very first field, pcs_co_file_close(file) deallocates it */
	struct pcs_process *proc;

	/* the underlying transport */
	struct pcs_co_file *raw_sock;

	SSL_CTX *ctx;
	SSL *ssl;
	pthread_mutex_t ssl_mutex;	/* protects SSL state */
	char *hostname;

	struct {
		unsigned int depth;
		int (*get_certs)(struct pcs_co_file *sock, X509 ***certs, X509_CRL ***crls);

		int (*cb)(struct pcs_co_file *sock, X509_STORE_CTX *ctx, int verify_cert_result);
	} verify_peer;

	/* network rx/tx queue */
	struct pcs_co_mutex tx_co_mutex, rx_co_mutex;
	struct bufqueue rx_bq;			/* net rx: data read from raw socket and awaiting decoding by SSL */
	struct bufqueue tx_bq;			/* net tx: data encoded by SSL and ready to be sent to raw socket */
	struct bufqueue u_rx_bq;		/* user rx: data decoded by SSL and ready to be read by user */
	int rx_shutdown, tx_shutdown;
	pthread_mutex_t rx_mutex, tx_mutex;	/* protects corresponing rx_XXX/tx_XXX vars */
	int tx_need_push;

	int state;
#define SOCKSTATE_INIT			(-1)
#define SOCKSTATE_CONNECTING		(0)
#define SOCKSTATE_ACCEPTING		(1)
#define SOCKSTATE_NORMAL		(2)	/* doing IO with SSL_{read,write}() */
#define SOCKSTATE_DEAD			(4)

	u16 offload_job_hash;

	u32 u_rx_size_limit;
	u32 rx_size_limit;
	u32 tx_size_limit;

	char rx_buf[12*1024];	/* small temp buffer for rx to avoid frequent large allocations as we rarely see > 12KB reads in production */

	/* An error message describing the last SSL failure, as returned by ERR_error_string(). */
	char err_msg[128];
};

static void save_last_ssl_error_string(struct pcs_ssl_socket *sock)
{
	unsigned long err = ERR_peek_last_error();
	ERR_error_string_n(err, sock->err_msg, sizeof(sock->err_msg));
}

static void save_last_os_error_string(struct pcs_ssl_socket *sock, int err)
{
	char msg[64];
	pcs_sys_strerror_r(-err, msg, sizeof(msg));
	snprintf(sock->err_msg, sizeof(sock->err_msg), "os error %i (%s)", err, msg);
}

const char *pcs_ssl_socket_err_msg(struct pcs_co_file *file)
{
	struct pcs_ssl_socket *sock = file2sock(file);
	return sock->err_msg;
}

static struct pcs_co_file_ops pcs_co_file_ssl_ops;

/*================ bio ================*/

static inline struct pcs_ssl_socket *sock_from_bio(BIO *b)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000
	return BIO_get_data(b);
#else
	return b->ptr;
#endif
}

static int do_network_read(struct pcs_ssl_socket *sock, int *timeout, int ioflags);
static int do_network_write(struct pcs_ssl_socket *sock, int *timeout, int ioflags);

static int pcs_bio_read(BIO *b, char *buf, int _len)
{
	struct pcs_ssl_socket *sock = sock_from_bio(b);
	u32 len = (u32)_len, sz = 0;

	if (pthread_mutex_trylock(&sock->rx_mutex))
		goto done;

	if (bufqueue_get_size(&sock->rx_bq) == 0)
		do_network_read(sock, NULL, CO_IO_NOWAIT);
	sz = bufqueue_get_copy(&sock->rx_bq, buf, len);
	pthread_mutex_unlock(&sock->rx_mutex);

done:
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
	struct pcs_ssl_socket *sock = sock_from_bio(b);
	u32 written = 0;

	if (pthread_mutex_trylock(&sock->tx_mutex))
		goto done;
	u32 bqsz = bufqueue_get_size(&sock->tx_bq);
	if (bqsz >= sock->tx_size_limit)
		goto unlock;

	written = len;

	/* try not to send in very small portions:
	 * most send attempts are rejected, so that makes sense to accumulate more data and to have higher success rate*/
	if (bqsz + len < sock->tx_size_limit) {
		bufqueue_put_copy(&sock->tx_bq, buf, len);
		goto unlock;
	}

	bufqueue_put_reference(&sock->tx_bq, buf, len);
	do_network_write(sock, NULL, CO_IO_NOWAIT);
	bufqueue_copy_referenced(&sock->tx_bq);

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

static BIO* make_bio(struct pcs_ssl_socket *sock)
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

/*================ peer certificate verification ================*/

static int pcs_x509_store_ctx_idx = -1;

static void pcs_ssl_socket_init_peer_verification(void)
{
	pcs_x509_store_ctx_idx = X509_STORE_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
}

static STACK_OF(X509_CRL)* pcs_ssl_socket_lookup_crls(X509_STORE_CTX *ctx, X509_NAME *name)
{
	struct pcs_ssl_socket *sock = X509_STORE_CTX_get_ex_data(ctx, pcs_x509_store_ctx_idx);
#if OPENSSL_VERSION_NUMBER >= 0x10100000
	if (!sock)
		return X509_STORE_CTX_get1_crls(ctx, name);
#endif

	X509 **certs;
	X509_CRL **crls;

	int r = sock->verify_peer.get_certs(&sock->file, &certs, &crls);
	if (r < 0)
		return NULL;

	(void) certs;
	int nr_crls = r;

	/* note that the certificate verification routine in OpenSSL will assume the ownership of this stack */
	STACK_OF(X509_CRL) *result = sk_X509_CRL_new_null();

	int i;
	for (i = 0; i < nr_crls; ++i) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000
		X509_CRL_up_ref(crls[i]);
#else
		CRYPTO_add(&crls[i]->references, 1, CRYPTO_LOCK_X509_CRL);
#endif
		r = sk_X509_CRL_push(result, crls[i]);
		BUG_ON(r == 0); /* this is CHECK_ALLOC, in fact */
	}

	return result;
}

static int no_crl_check(X509_STORE_CTX *ctx, X509_CRL *crl)
{
	return 1;
}

int pcs_ssl_socket_verify_peer_cert_cb(X509_STORE_CTX *ctx, void *arg)
{
	struct pcs_ssl_socket *sock = arg;

	/**
	   Note that CRLs installed with X509_STORE_add_crl() into a SSL_CTX will live as long as there
	   is a socket using that context. This is undesirable in environments where big CRL are regularly
	   reloaded. To avoid keeping references to outdated CRLs, we install a custom CRL lookup callback.
	   That callback returns the most recently loaded CRLs.
	 */

	X509_STORE_CTX_set_ex_data(ctx, pcs_x509_store_ctx_idx, sock);

#if OPENSSL_VERSION_NUMBER < 0x10100000
	/* Checking CRLs normally happens upon every handshake. As CRLs may be big, checking them
	   is an expensive procedure, so we disable the checks, and expect a user to run them upon
	   loading CRLs. */
	ctx->lookup_crls = pcs_ssl_socket_lookup_crls;
	ctx->check_crl = no_crl_check;
#endif

	int r = X509_verify_cert(ctx);
	if (sock->verify_peer.cb != NULL)
		r = sock->verify_peer.cb(&sock->file, ctx, r);
	return r;
}

/*================ public API ================*/

#if !defined(_ACRONIS_OPENSSL_PATCHES) && OPENSSL_VERSION_NUMBER < 0x10100000

/* OpenSSL 1.1+ don't use these callbacks at all, prev versions have 41 mutex */
static pthread_mutex_t ssl_locking_mtx[64];

static void ssl_locking_callback(int mode, int type, const char* file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&ssl_locking_mtx[type]);
	else if (mode & CRYPTO_UNLOCK)
		pthread_mutex_unlock(&ssl_locking_mtx[type]);
}

static void ssl_thread_id(CRYPTO_THREADID *tid)
{
	CRYPTO_THREADID_set_numeric(tid, (unsigned long)pthread_self());
}

static void ssl_locking_init(void)
{
	/* For thread safety at least these 2 callbacks must be set. man CRYPTO_set_locking_callback for more info */
	int i, nr_locks = sizeof(ssl_locking_mtx) / sizeof(ssl_locking_mtx[0]);
	for (i = 0; i < nr_locks; i++)
		pthread_mutex_init(&ssl_locking_mtx[i], NULL);
	BUG_ON(CRYPTO_num_locks() > nr_locks);
	CRYPTO_set_locking_callback(ssl_locking_callback);
	CRYPTO_THREADID_set_callback(ssl_thread_id);
}

#else

static void ssl_locking_init(void)
{
}

#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000
static void *ssl_malloc(size_t sz) { return pcs_malloc(sz); }
static void *ssl_realloc(void *p, size_t sz) { return pcs_realloc(p, sz); }
static void ssl_free(void *p) { pcs_free(p); }
#else
static void *ssl_malloc(size_t sz, const char *file, int line) { return pcs_malloc(sz); }
static void *ssl_realloc(void *p, size_t sz, const char *file, int line) { return pcs_realloc(p, sz); }
static void ssl_free(void *p, const char *file, int line) { pcs_free(p); }
#endif

static void pcs_ssl_init_lib(void)
{
	static int initialised = 0;
	if (initialised)
		return;

	CRYPTO_set_mem_functions(ssl_malloc, ssl_realloc, ssl_free);

	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	ssl_locking_init();

	struct {
		unsigned int major;
		unsigned int minor;
	} compile_time, run_time;

	compile_time.major = (OPENSSL_VERSION_NUMBER & 0xF0000000) >> 28;
	compile_time.minor = (OPENSSL_VERSION_NUMBER & 0x0FF00000) >> 20;

	const char *ssl_version_string = SSLeay_version(SSLEAY_VERSION);
	if (sscanf(ssl_version_string, "OpenSSL %u.%u.", &run_time.major, &run_time.minor) != 2)
		pcs_fatal("Failed to parse the OpenSSL version string '%s'.", ssl_version_string);

	if (compile_time.major != run_time.major ||
	    compile_time.minor != run_time.minor)
	{
		/* As per http://openssl.org/docs/faq.html#MISC8 , binary compatibility is
		   guaranteed only between versions x.y.*.* */
		pcs_fatal("PCS is compiled for systems with OpenSSL versions %u.%u.*, and your system has '%s'.\n"
			  "These versions may not be binary compatible.\n"
			  "Please install a PCS version that is appropriate for your system.",
			  compile_time.major, compile_time.minor,
			  ssl_version_string);
	}

	pcs_ssl_socket_init_peer_verification();

	initialised = 1;
}

void pcs_ssl_init(void)
{
	pcs_ssl_init_lib();
	pcs_network_init();
}

static u16 next_job_hash;

struct pcs_co_file* pcs_ssl_socket(struct pcs_co_file *raw_socket)
{
	struct pcs_ssl_socket *sock = pcs_xzmalloc(sizeof(*sock));

	sock->proc = pcs_current_proc;

#if OPENSSL_VERSION_NUMBER >= 0x10100000
	sock->ctx = SSL_CTX_new(TLS_method());
#else
	/* SSLv23_method() can negotiate any SSL/TLS version depending on context options.
	   Never use TLSv1_method() because it is for TLS 1.0 only! */
	sock->ctx = SSL_CTX_new(SSLv23_method());
#endif
	CHECK_ALLOC(sock->ctx);

	sock->state = SOCKSTATE_INIT;

	sock->raw_sock = raw_socket;

	bufqueue_init(&sock->u_rx_bq);
	sock->u_rx_size_limit = BUF_U_RX_LIMIT;

	bufqueue_init(&sock->rx_bq);
	sock->rx_size_limit = BUF_RX_LIMIT;
	sock->rx_bq.prealloc_size = sock->rx_size_limit / 4;;

	bufqueue_init(&sock->tx_bq);
	sock->tx_size_limit = BUF_TX_LIMIT;
	sock->tx_bq.prealloc_size = sock->tx_size_limit / 4;

	pcs_co_mutex_init(&sock->rx_co_mutex);
	pcs_co_mutex_init(&sock->tx_co_mutex);
	pthread_mutex_init(&sock->ssl_mutex, NULL);
	pthread_mutex_init(&sock->rx_mutex, NULL);
	pthread_mutex_init(&sock->tx_mutex, NULL);

	sock->offload_job_hash = next_job_hash++;

	/* SSL options are set as in CURL, file lib/vtls/openssl.c:ossl_connect_step1() .
	   The difference is that we enable no protocol bug workarounds. */
	SSL_CTX_set_options(sock->ctx, SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	//SSL_set_cipher_list(sock->ssl, "DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:ALL");

	sock->verify_peer.depth = 0;
	SSL_CTX_set_verify(sock->ctx, SSL_VERIFY_NONE, 0);

	SSL_CTX_set_read_ahead(sock->ctx, BUF_RX_LIMIT / 4);
//	SSL_set_read_ahead(sock->ctx, 1);

	pcs_co_file_init(&sock->file, &pcs_co_file_ssl_ops);

	return &sock->file;
}

struct pcs_co_file* pcs_ssl_socket_from_fd(pcs_sock_t sock)
{
	return pcs_ssl_socket(pcs_co_file_alloc_socket(sock));
}

static void pcs_ssl_socket_free(struct pcs_ssl_socket *sock)
{
	sock->state = SOCKSTATE_DEAD;

	bufqueue_clear(&sock->u_rx_bq);
	bufqueue_clear(&sock->rx_bq);
	bufqueue_clear(&sock->tx_bq);
	pthread_mutex_destroy(&sock->ssl_mutex);
	pthread_mutex_destroy(&sock->rx_mutex);
	pthread_mutex_destroy(&sock->tx_mutex);

	SSL_free(sock->ssl);
	SSL_CTX_free(sock->ctx);
	pcs_free(sock->hostname);

	memset(sock, 0x55, sizeof(*sock));
	pcs_free(sock);
}

void pcs_ssl_socket_set_allowed_methods(struct pcs_co_file *file, int methods)
{
#if OPENSSL_VERSION_NUMBER >= 0x10001000
	struct pcs_ssl_socket *sock = file2sock(file);
	switch (methods) {
		case SSL_METHOD_TLS_1 | SSL_METHOD_TLS_1_1 | SSL_METHOD_TLS_1_2:
			SSL_CTX_clear_options(sock->ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
			break;

		case SSL_METHOD_TLS_1_1 | SSL_METHOD_TLS_1_2:
			SSL_CTX_set_options(sock->ctx, SSL_OP_NO_TLSv1);
			SSL_CTX_clear_options(sock->ctx, SSL_OP_NO_TLSv1_1);
			break;

		case SSL_METHOD_TLS_1_2:
			SSL_CTX_set_options(sock->ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
			break;

		default:
			BUG();
	}
#endif
}

int pcs_ssl_socket_set_cert(struct pcs_co_file *file, X509 *cert, EVP_PKEY *key)
{
	struct pcs_ssl_socket *sock = file2sock(file);
	BUG_ON(cert == NULL || key == NULL);

	if (SSL_CTX_use_certificate(sock->ctx, cert) != 1 ||
	    SSL_CTX_use_PrivateKey(sock->ctx, key) != 1 ||
	    !SSL_CTX_check_private_key(sock->ctx))
	{
		save_last_ssl_error_string(sock);
		ERR_clear_error();
		return -PCS_ERR_INVALID;
	}

	return 0;
}

int pcs_ssl_socket_set_server_name_indication(struct pcs_co_file *file, const char *value)
{
	struct pcs_ssl_socket *sock = file2sock(file);
	pcs_free(sock->hostname);
	sock->hostname = pcs_xstrdup(value);
	return 0;
}

int pcs_ssl_socket_set_verify_peer(struct pcs_co_file *file, unsigned int depth,
		int (*get_certs)(struct pcs_co_file *file, X509 ***certs, X509_CRL ***crls), u8 require_peer_cert)
{
	struct pcs_ssl_socket *sock = file2sock(file);

	sock->verify_peer.depth = depth;
	sock->verify_peer.get_certs = get_certs;

	int verify_flags = SSL_VERIFY_PEER;
	if (require_peer_cert)
		verify_flags |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

	SSL_CTX_set_verify(sock->ctx, verify_flags, 0);
	SSL_CTX_set_verify_depth(sock->ctx, depth);
	SSL_CTX_set_cert_verify_callback(sock->ctx, &pcs_ssl_socket_verify_peer_cert_cb, sock);

	X509_STORE *cert_store = SSL_CTX_get_cert_store(sock->ctx);
	CHECK_ALLOC(cert_store);

	X509 **certs;
	X509_CRL **crls;
	int r = get_certs(&sock->file, &certs, &crls);
	if (r < 0) {
		snprintf(sock->err_msg, sizeof(sock->err_msg), "failed to set the chain of trust: get_certs() failed with error %i (%s)", r, pcs_strerror(r));
		return r;
	}

	(void) crls;
	unsigned int nr_trusted_certs = r;

	unsigned int i;
	for (i = 0; i < nr_trusted_certs; ++i) {
		if (X509_STORE_add_cert(cert_store, certs[i]) != 1) {
			unsigned long err = ERR_get_error();
			if (ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
				ERR_clear_error();
				continue;
			}
			save_last_ssl_error_string(sock);
			ERR_clear_error();
			return -PCS_ERR_INVALID;
		}
	}

	X509_STORE_set_flags(cert_store, X509_V_FLAG_CRL_CHECK);

	return 0;
}

void pcs_ssl_socket_set_verify_peer_cb(struct pcs_co_file *file, int (*cb)(struct pcs_co_file *file, X509_STORE_CTX *ctx, int verify_cert_result))
{
	struct pcs_ssl_socket *sock = file2sock(file);
	sock->verify_peer.cb = cb;

#if OPENSSL_VERSION_NUMBER >= 0x10100000
	X509_STORE *cert_store = SSL_CTX_get_cert_store(sock->ctx);
	CHECK_ALLOC(cert_store);

	/* Checking CRLs normally happens upon every handshake. As CRLs may be big, checking them
	   is an expensive procedure, so we disable the checks, and expect a user to run them upon
	   loading CRLs. */
	X509_STORE_set_lookup_crls(cert_store, pcs_ssl_socket_lookup_crls);
	X509_STORE_set_check_crl(cert_store, no_crl_check);
#endif
}

X509* pcs_ssl_socket_get_peer_cert(struct pcs_co_file *file)
{
	struct pcs_ssl_socket *sock = file2sock(file);
	return SSL_get_peer_certificate(sock->ssl);
}

struct io_op {
#define OP_READ		1
#define OP_WRITE	2
#define OP_CONNECT	3
#define OP_ACCEPT	4
#define OP_SHUTDOWN	5
	int code;
	void *buf;
	int min_size;	/* min size to read */
	int size;	/* size left in buffer */
	int total;	/* total processed */
	unsigned long ssl_err;
	int sys_err;	/* system error / errno */
	int *timeout;
};

/* called under sock->rx_mutex */
static int do_network_read(struct pcs_ssl_socket *sock, int *timeout, int ioflags)
{
	if (sock->rx_shutdown)
		return 0;

	/* can race with bio_read or another SSL op already requested the data via WANT_READ */
	if (bufqueue_get_size(&sock->rx_bq) > 0)
		return 1;	/* report some progress, actual number of bytes not important */

	int ret = pcs_co_file_read_ex(sock->raw_sock, sock->rx_buf, sizeof(sock->rx_buf), 0, timeout, ioflags);

	if (ret > 0) {
		bufqueue_put_copy(&sock->rx_bq, sock->rx_buf, ret);
	} else if (ret == 0 && !(ioflags & CO_IO_NOWAIT)) {
		sock->rx_shutdown = 1;
	}

	return ret;
}

/* called under sock->tx_mutex, returns <0 error, =0 nothing done, >0 smth was written */
static int do_network_write(struct pcs_ssl_socket *sock, int *timeout, int ioflags)
{
	if (sock->tx_shutdown)	/* NOTE: it's negative error code */
		return sock->tx_shutdown;

	int size = bufqueue_get_size(&sock->tx_bq);
	if (!size)
		return 0;

	void *buf = pcs_xmalloc(size);
	bufqueue_peek_range(&sock->tx_bq, 0, size, buf);

	int ret = pcs_co_file_write_ex(sock->raw_sock, buf, size, 0, timeout, ioflags);
	BUG_ON(!ioflags && ret >= 0 && ret != size);
	pcs_free(buf);

	if (ret < 0)
		sock->tx_shutdown = ret;
	else {
		bufqueue_drain(&sock->tx_bq, ret);
		sock->tx_need_push = 1;
	}

	return ret;
}

static void ssl_sock_push(struct pcs_ssl_socket *sock)
{
	if (!sock->tx_need_push)
		return;

	pcs_sock_push(pcs_co_file_sock(sock->raw_sock));
	sock->tx_need_push = 0;
}

static int pcs_ssl_check_io(struct pcs_ssl_socket *sock, struct io_op *op, int rc)
{
	int r = 0, w = 0;

	/* TODO minor: when there is smth in tx_bq, but SSL didn't ask for WANT_WRITE, then we'd better
	 * perform async writes from special writer co. I think this is minor however */
	if (rc == SSL_ERROR_WANT_WRITE || bufqueue_get_size(&sock->tx_bq)) {
		pcs_co_mutex_lock(&sock->tx_co_mutex);
		pthread_mutex_lock(&sock->tx_mutex);
		w = do_network_write(sock, op->timeout, 0);
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
		r = do_network_read(sock, op->timeout, CO_IO_PARTIAL);
		pthread_mutex_unlock(&sock->rx_mutex);
		pcs_co_mutex_unlock(&sock->rx_co_mutex);
		if (r < 0)
			return r;
	}
	return r + w;
}

static int ssl_op_error(struct io_op *op)
{
	int reason = ERR_GET_REASON(op->ssl_err);
	int rc = PCS_ERR_UNKNOWN;

	switch (reason) {
	case SSL_AD_REASON_OFFSET + SSL_AD_CERTIFICATE_EXPIRED: rc = PCS_ERR_SSL_CERTIFICATE_EXPIRED; break;
	case SSL_AD_REASON_OFFSET + SSL_AD_CERTIFICATE_REVOKED: rc = PCS_ERR_SSL_CERTIFICATE_REVOKED; break;
	case SSL_AD_REASON_OFFSET + SSL_AD_UNKNOWN_CA:          rc = PCS_ERR_SSL_UNKNOWN_CA; break;
	default:
		if (op->code == OP_CONNECT || op->code == OP_ACCEPT)
			rc = PCS_ERR_AUTH;
		else
			rc = PCS_ERR_NET;
	}
	return rc;
}

static int pcs_ssl_socket_op_thread_locked(struct pcs_ssl_socket *sock, struct io_op *op)
{
	int err = 0;

	switch (op->code) {
	case OP_READ:
		while (op->size) {
			err = SSL_read(sock->ssl, (char *)op->buf + op->total, op->size);
			if (err <= 0)
				break;

			op->total += err;
			op->size -= err;
		}
		break;
	case OP_WRITE:
		while (op->size) {
			err = SSL_write(sock->ssl, (char *)op->buf + op->total, op->size);
			if (err <= 0)
				break;

			op->total += err;
			op->size -= err;
		}
		break;
	case OP_CONNECT:
		err = SSL_connect(sock->ssl);
		op->size = err > 0 ? 0 : 1;
		op->total = 1 - op->size;	/* 1 done, 0 - not done */
		break;
	case OP_ACCEPT:
		err = SSL_accept(sock->ssl);
		op->size = err > 0 ? 0 : 1;
		op->total = 1 - op->size;	/* 1 done, 0 - not done */
		break;
	case OP_SHUTDOWN:
		err = SSL_shutdown(sock->ssl);
		op->size = err > 0 ? 0 : 1;
		op->total = 1 - op->size;	/* 1 done, 0 - not done */
		break;
	}

	if ((sock->tx_need_push || bufqueue_get_size(&sock->tx_bq)) && !pthread_mutex_trylock(&sock->tx_mutex)) {
		do_network_write(sock, NULL, CO_IO_NOWAIT);
		ssl_sock_push(sock);	/* push everything that was written by operations above + do_network_write */
		pthread_mutex_unlock(&sock->tx_mutex);
	}

	if (err > 0) {
		err = 0;
		op->ssl_err = 0;
	} else if (err <= 0) {
		err = SSL_get_error(sock->ssl, err);

		/* save detailed error status also */
		save_last_ssl_error_string(sock);
		op->ssl_err = ERR_get_error();
		ERR_clear_error();
	}

	return err;
}

static int pcs_ssl_socket_op_thread(struct pcs_ssl_socket *sock, struct io_op *op)
{
	pthread_mutex_lock(&sock->ssl_mutex);
	int res = pcs_ssl_socket_op_thread_locked(sock, op);
	pthread_mutex_unlock(&sock->ssl_mutex);
	return res;
}

static int pcs_ssl_socket_op_co(struct pcs_ssl_socket *sock, struct io_op *op)
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
		if ((op->code == OP_READ || op->code == OP_WRITE) && op->size <= 1024 && !pthread_mutex_trylock(&sock->ssl_mutex)) {
			ssl_rc = pcs_ssl_socket_op_thread_locked(sock, op);
			pthread_mutex_unlock(&sock->ssl_mutex);
		} else {
			struct pcs_coroutine *co = pcs_co_migrate_to_thread_hash(sock->proc->co_ssl, sock->offload_job_hash);
			ssl_rc = pcs_ssl_socket_op_thread(sock, op);
			pcs_co_migrate_from_thread(co);
		}

		if (op->code == OP_READ && ssl_rc == SSL_ERROR_ZERO_RETURN)
			break;
		/* we read min_size requested, further reads will block */
		if (op->code == OP_READ && op->total >= op->min_size && ssl_rc == SSL_ERROR_WANT_READ)
			break;

		io_rc = pcs_ssl_check_io(sock, op, ssl_rc);
		if (io_rc > 0)		/* did some I/O, restart */
			continue;
		if (io_rc < 0) {
			save_last_os_error_string(sock, io_rc);
			op->sys_err = io_rc;
			return -pcs_errno_to_err(-io_rc);
		}

		if (!ssl_rc)
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

static int pcs_ssl_socket_co_handshake(struct pcs_ssl_socket *sock, int handshake_state, int *timeout)
{
	BUG_ON(sock->state != SOCKSTATE_INIT);
	BUG_ON(!sock->proc->co_ssl);

	sock->ssl = SSL_new(sock->ctx);
	CHECK_ALLOC(sock->ssl);
	SSL_set_bio(sock->ssl, make_bio(sock), make_bio(sock));
	if (sock->hostname)
		SSL_set_tlsext_host_name(sock->ssl, sock->hostname);

	sock->state = handshake_state;

	struct io_op op = {
		.code = (handshake_state == SOCKSTATE_CONNECTING ? OP_CONNECT : OP_ACCEPT),
		.buf = NULL,
		.size = 1,
		.timeout = timeout,
	};

	int err = pcs_ssl_socket_op_co(sock, &op);

	if (err < 0)
		return err;
	if (!err)
		return -PCS_ERR_NET;

	X509 *peer_cert = SSL_get_peer_certificate(sock->ssl);
	if (peer_cert != NULL) {
		X509_free(peer_cert);

		long int r = SSL_get_verify_result(sock->ssl);
		if (SSL_get_verify_mode(sock->ssl) != SSL_VERIFY_NONE && r != X509_V_OK) {
			snprintf(sock->err_msg, sizeof(sock->err_msg), "%s", X509_verify_cert_error_string(r));
			return -PCS_ERR_PEER_CERTIFICATE_REJECTED;
		}
	}

	return 0;
}

int pcs_ssl_socket_co_connect(struct pcs_co_file *file, int *timeout)
{
	struct pcs_ssl_socket *sock = file2sock(file);
	return pcs_ssl_socket_co_handshake(sock, SOCKSTATE_CONNECTING, timeout);
}

int pcs_ssl_socket_co_accept(struct pcs_co_file *file, int *timeout)
{
	struct pcs_ssl_socket *sock = file2sock(file);
	BUG_ON(sock->verify_peer.depth != 0 && sock->verify_peer.get_certs == NULL);

	return pcs_ssl_socket_co_handshake(sock, SOCKSTATE_ACCEPTING, timeout);
}

static int pcs_ssl_socket_co_read(struct pcs_co_file *file, void * buf, int size, u64 offset, int * timeout, u32 flags)
{
	struct pcs_ssl_socket *sock = file2sock(file);

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
			.timeout = timeout,
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
			.timeout = timeout,
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

static int pcs_ssl_socket_co_write(struct pcs_co_file *file, const void * buf, int size, u64 offset, int * timeout, u32 flags)
{
	BUG_ON(flags != 0); /* unsupported */
	struct pcs_ssl_socket *sock = file2sock(file);

	struct io_op op = {
		.code = OP_WRITE,
		.buf = (void *)buf,
		.size = size,
		.timeout = timeout,
		.total = 0
	};

	int rc = pcs_ssl_socket_op_co(sock, &op);
	return (rc < 0) ? op.sys_err : rc;
}

static int pcs_ssl_socket_co_close(struct pcs_co_file *file)
{
	struct pcs_ssl_socket *sock = file2sock(file);

	if (sock->state != SOCKSTATE_INIT && !sock->tx_shutdown) {
		struct io_op op = {
			.code = OP_SHUTDOWN,
			.timeout = NULL,	/* TODO: can use timeout actually... */
			.size = 1
		};

		pcs_ssl_socket_op_co(sock, &op);
	}

	pcs_co_file_close(sock->raw_sock);
	pcs_ssl_socket_free(sock);

	return 0;
}

static struct pcs_co_file_ops pcs_co_file_ssl_ops = {
	.read			= pcs_ssl_socket_co_read,
	.write			= pcs_ssl_socket_co_write,
	.close			= pcs_ssl_socket_co_close
};
