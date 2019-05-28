/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */


#ifndef _SSL_HELPERS_INCLUDED_H

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "pcs_types.h"

#define PCS_SSL_PRIVATE_KEY_LEN	2048

/* generate pair (private and public) of RSA keys */
PCS_API EVP_PKEY* pcs_gen_rsa_pkey(int key_len);
/* print X509 certificate */
PCS_API void pcs_print_cert(int log_level, X509* c);
/* convert X509 certificate to PEM format */
PCS_API char* pcs_cert_to_pem(X509 *c);
/* convert private key to PEM format */
PCS_API char * pcs_pkey_to_pem(EVP_PKEY *key);
/* read X509 certificate from PEM */
PCS_API X509* pcs_cert_from_pem(const char *pem, int *out_sz);
PCS_API int pcs_cert_from_pem_file(const char *path, X509 **res);
/* read private key from PEM */
PCS_API EVP_PKEY *pcs_pkey_from_pem(const char *pem, int *out_sz);
PCS_API int pcs_pkey_from_pem_file(const char *path, EVP_PKEY **res);
/* read a CRL from PEM */
PCS_API X509_CRL* pcs_crl_from_pem(const char *pem, int *out_sz);
PCS_API int pcs_crl_from_pem_file(const char *path, X509_CRL **res);
/* create X509 certificate and sign it by pkey */
X509* pcs_create_cert(EVP_PKEY *pkey, const unsigned char *cn);
/* free resources used by EVP_PKEY private key*/
PCS_API void pcs_free_pkey(EVP_PKEY *pkey);
/* free resources used by X509 certificate */
PCS_API void pcs_free_cert(X509 *cert);
/* free resources used by a CRL */
PCS_API void pcs_free_crl(X509_CRL *crl);

PCS_API void pcs_ssl_print_error(int log_lvl, const char *msg);

/* returns len of bytes are writen for @out */
PCS_API int base64_encode(const char *input, int input_len, char *out, int outl);
PCS_API int base64_decode(const char *input, int len, unsigned char *out);

#endif
