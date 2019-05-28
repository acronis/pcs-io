/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#include "pcs_co_io.h"

struct pcs_ssl_socket {
	struct pcs_co_file file;

	/* the underlying transport */
	struct pcs_co_file *raw_sock;

	SSL_CTX *ctx;
	SSL *ssl;
	char *hostname;

	struct {
		int (*cb)(void *arg, SSL *ssl, int *alert);
		void *arg;
	} client_hello;

	struct {
		unsigned int depth;
		int (*get_certs)(void *arg, X509 ***certs, X509_CRL ***crls);
		void *arg;

		int (*cb)(struct pcs_co_file *sock, X509_STORE_CTX *ctx, int verify_cert_result);
	} verify_peer;

	int state;
#define SOCKSTATE_INIT			(-1)
#define SOCKSTATE_CONNECTING		(0)
#define SOCKSTATE_ACCEPTING		(1)
#define SOCKSTATE_NORMAL		(2)	/* doing IO with SSL_{read,write}() */
#define SOCKSTATE_DEAD			(4)

	int (*handshake)(struct pcs_ssl_socket *sock);

	/* An error message describing the last SSL failure, as returned by ERR_error_string(). */
	char err_msg[128];
};

void save_last_ssl_error_string(struct pcs_ssl_socket *sock, unsigned long err);
void save_last_os_error_string(struct pcs_ssl_socket *sock, int err);
struct pcs_co_file* pcs_ssl_socket_st(struct pcs_co_file *raw_socket);
struct pcs_co_file* pcs_ssl_socket_mt(struct pcs_co_file *raw_socket);
void pcs_ssl_socket_init(struct pcs_ssl_socket *sock);
void pcs_ssl_socket_fini(struct pcs_ssl_socket *sock);
