/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_sock_ssl_priv.h"
#include "pcs_sock_ssl.h"
#include "pcs_malloc.h"
#include "log.h"
#include "bug.h"

#define file2sock(f) container_of(f, struct pcs_ssl_socket, file)

void save_last_ssl_error_string(struct pcs_ssl_socket *sock, unsigned long err)
{
	ERR_error_string_n(err, sock->err_msg, sizeof(sock->err_msg));
}

void save_last_os_error_string(struct pcs_ssl_socket *sock, int err)
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

struct pcs_co_file* pcs_ssl_socket(struct pcs_co_file *raw_socket)
{
	if (pcs_current_proc->co_ssl)
		return pcs_ssl_socket_st(raw_socket);
	else
		return pcs_ssl_socket_mt(raw_socket);
}

void pcs_ssl_socket_init(struct pcs_ssl_socket *sock)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000
	sock->ctx = SSL_CTX_new(TLS_method());
#else
	/* SSLv23_method() can negotiate any SSL/TLS version depending on context options.
	   Never use TLSv1_method() because it is for TLS 1.0 only! */
	sock->ctx = SSL_CTX_new(SSLv23_method());
#endif
	CHECK_ALLOC(sock->ctx);

	sock->state = SOCKSTATE_INIT;

	/* SSL options are set as in CURL, file lib/vtls/openssl.c:ossl_connect_step1() .
	   The difference is that we enable no protocol bug workarounds. */
	SSL_CTX_set_options(sock->ctx, SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	//SSL_set_cipher_list(sock->ssl, "DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:ALL");

	sock->verify_peer.depth = 0;
	SSL_CTX_set_verify(sock->ctx, SSL_VERIFY_NONE, 0);

	SSL_CTX_set_read_ahead(sock->ctx, 1);
}

struct pcs_co_file* pcs_ssl_socket_from_fd(pcs_sock_t sock)
{
	return pcs_ssl_socket(pcs_co_file_alloc_socket(sock));
}

void pcs_ssl_socket_fini(struct pcs_ssl_socket *sock)
{
	sock->state = SOCKSTATE_DEAD;

	SSL_free(sock->ssl);
	SSL_CTX_free(sock->ctx);
	pcs_free(sock->hostname);
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
		save_last_ssl_error_string(sock, ERR_get_error());
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
			save_last_ssl_error_string(sock, ERR_get_error());
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

static int pcs_ssl_socket_co_handshake(struct pcs_ssl_socket *sock, int handshake_state)
{
	BUG_ON(sock->state != SOCKSTATE_INIT);

	sock->ssl = SSL_new(sock->ctx);
	CHECK_ALLOC(sock->ssl);
	if (sock->hostname)
		SSL_set_tlsext_host_name(sock->ssl, sock->hostname);

	sock->state = handshake_state;

	int err = sock->handshake(sock);
	if (err)
		return err;

	X509 *peer_cert = SSL_get_peer_certificate(sock->ssl);
	if (peer_cert != NULL) {
		X509_free(peer_cert);

		long int r = SSL_get_verify_result(sock->ssl);
		if (SSL_get_verify_mode(sock->ssl) != SSL_VERIFY_NONE && r != X509_V_OK) {
			snprintf(sock->err_msg, sizeof(sock->err_msg), "%s", X509_verify_cert_error_string(r));
			return -PCS_ERR_PEER_CERTIFICATE_REJECTED;
		}
	}

	sock->state = SOCKSTATE_NORMAL;
	return 0;
}

int pcs_ssl_socket_co_connect(struct pcs_co_file *file)
{
	struct pcs_ssl_socket *sock = file2sock(file);
	return pcs_ssl_socket_co_handshake(sock, SOCKSTATE_CONNECTING);
}

int pcs_ssl_socket_co_accept(struct pcs_co_file *file)
{
	struct pcs_ssl_socket *sock = file2sock(file);
	BUG_ON(sock->verify_peer.depth != 0 && sock->verify_peer.get_certs == NULL);

	return pcs_ssl_socket_co_handshake(sock, SOCKSTATE_ACCEPTING);
}
