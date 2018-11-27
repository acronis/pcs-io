/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#pragma once

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "pcs_types.h"
#include "pcs_sock.h"
#include "pcs_co_io.h"
#include "pcs_error.h"

/* system error code returned by read/write/close from SSL socket, i.e. some arbitrary errno not used by anybody */
#define PCS_ESSL	99999

/**
   A secure socket.

   ## General

   The socket is intended to be used in the following way:
   1. Establish a TCP connection, or accept one.
   2. Pass the raw TCP socket to pcs_ssl_socket().
   3. Specify a private key, and a certificate by calling pcs_ssl_socket_set_cert().
      Optionally, request the peer's certificate verification by calling pcs_ssl_socket_set_verify_peer(),
      and provide a list of certificates that comprise the chain of trust.
   4. Call pcs_ssl_co_connect() or pcs_ssl_co_accept() to perform a client-side or a server-side
      handshake, respectively.
   5. Use standart pcs_co_file_read / write / close to perform I/O on this socket.

   Note that pcs_ssl_socket does not allow to accept clients without a certificate.

   ## Error handling

   See pcs_ssl_socket_co_connect() and pcs_ssl_socket_co_accept() for the list of errors that may
   occur during a handshake.

 */
struct bufqueue;

/* Must be called on app init */
PCS_API void pcs_ssl_init(void);

/**
   Create a secure socket that will use @raw_socket as the underlying transport.
   The caller must then initiate a secure session by calling pcs_ssl_socket_co_connect()
   or pcs_ssl_socket_co_accept().

   By default the socket will allow only TLS 1 or higher.

   The socket @raw_socket will be owned by pcs_ssl_socket.
*/
PCS_API struct pcs_co_file* pcs_ssl_socket(struct pcs_co_file *sock);
PCS_API struct pcs_co_file* pcs_ssl_socket_from_fd(pcs_sock_t sock);

/* Specify which TLS versions are allowed for @sock. */
PCS_API void pcs_ssl_socket_set_allowed_methods(struct pcs_co_file *sock, int methods);
#define SSL_METHOD_TLS_1   (1U << 0)
#define SSL_METHOD_TLS_1_1 (1U << 1)
#define SSL_METHOD_TLS_1_2 (1U << 2)

/**
   Set a certificate, and the private key of it.

   \param @sock ssl socket to configure; it must have no certificate previously installed
   \param @cert a certificate to use
   \returns 0 if successful
            -PCS_ERR_INVALID if the certificate can not be installed, or @cert and @key do not match
 */
PCS_API int pcs_ssl_socket_set_cert(struct pcs_co_file *sock, X509 *cert, EVP_PKEY *key);

PCS_API int pcs_ssl_socket_set_server_name_indication(struct pcs_co_file *sock, const char *value);

/**
   Require that a peer send a certificate during the handshake, and verify that certificate
   against a chain of trust provided by @get_certs.

   WARNING: pcs_ssl_socket disables OpenSSL's checks of the validity of CRLs to improve the performance.
   A user must make sure that @get_certs() supplies certificates and CRLs that are valid.

   \param @sock ssl socket to configure
   \param @depth the number of certificates in the chain of trust
   \param @get_certs a function that returns an array of @depth certificates that comprise the chain of trust,
                     and corresponding CRLs; the function may return PCS_ERR_* codes to indicate success/failure
   \param @require_peer_cert terminate TLS/SSL handshake if the client did not return a peer certificate
   \returns 0 if successful
            PCS_ERR_INVALID if certificates returned by @get_certs can't be installed to the socket's X509 store
            any other error that @get_certs may return
 */
PCS_API int pcs_ssl_socket_set_verify_peer(struct pcs_co_file *sock, unsigned int depth,
		int (*get_certs)(struct pcs_co_file *sock, X509 ***certs, X509_CRL ***crls), u8 require_peer_cert);

/**
   Install a function that will be callled after the verification of the peer certificate.
   The callback receives X509 store context, and the return value of X509_verify_cert(). It may
   analyse and modify the result of the certificate verification.

   If @depth is non-zero, a valid client certificate is required. If it is zero, then clients may
   connect without supplying a certificate.

   \sa X509_STORE_CTX_get_error()
   \sa X509_STORE_CTX_set_error()

   The return value from @cb() will be used as the return value of the socket's certificate
   verification callback.

   \sa SSL_CTX_set_cert_verify_callback()

   \param @sock ssl socket to configure
   \param @cb a callback to be run after the peer's certificate is verified by X509_verify_cert()
 */
PCS_API void pcs_ssl_socket_set_verify_peer_cb(struct pcs_co_file *sock, int (*cb)(struct pcs_co_file *sock, X509_STORE_CTX *ctx, int verify_cert_result));

/* Get the peer's certificate, if one was supplied during the handshake. */
PCS_API X509* pcs_ssl_socket_get_peer_cert(struct pcs_co_file *sock);

/**
   Perform a client-side handshake.

   \param @sock ssl socket
   \param @timeout on entry, a timeout (in msecs) for the operation, NULL if infinite
                   on exit, the remaining time
   \returns 0 if successful,
            PCS_ERR_SSL_CERTIFICATE_REVOKED if the client certificate is revoked
            PCS_ERR_SSL_CERTIFICATE_EXPIRED if the client certificate is expired
            PCS_ERR_SSL_UNKNOWN_CA if the server can't match the client certificate agains a known CA
            PCS_ERR_AUTH if the server has rejected the handshake
            PCS_ERR_PEER_CERTIFICATE_REJECTED if the peer certificate verification failed
            PCS_ERR_AUTH_TIMEOUT if the timeout expired
            PCS_ERR_CANCELED if canceled with pcs_co_io_cancel()
            PCS_ERR_NET_ABORT or PCS_ERR_NET if there was a network error during the handshake
*/
PCS_API int pcs_ssl_socket_co_connect(struct pcs_co_file *sock, int *timeout);

/**
   Perform a server-side handshake.

   \param @sock ssl socket
   \returns 0 if successful
            PCS_ERR_PEER_CERTIFICATE_REJECTED if the peer certificate verification failed
            PCS_ERR_AUTH_TIMEOUT if the timeout expired
            PCS_ERR_CANCELED if canceled with pcs_co_io_cancel()
            PCS_ERR_NET_ABORT or PCS_ERR_NET if there was a network error during the handshake
*/
PCS_API int pcs_ssl_socket_co_accept(struct pcs_co_file *sock, int *timeout);

/**
   Get last error text message. Helpful for connect/accept erorrs.
*/
PCS_API const char *pcs_ssl_socket_err_msg(struct pcs_co_file *file);

/**
 * NOTE: beware, that unlike to all above functions pcs_co_file_read/write()/close() from SSL socket returns system errors!
 */
