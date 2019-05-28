/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */


#include "ssl_helpers.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "log.h"
#include "pcs_malloc.h"
#include "pcs_sync_io.h"

#define LIFETIME (60*60*24*365*50)  // 50 years, arbitrarily

EVP_PKEY* pcs_gen_rsa_pkey(int key_len)
{
	EVP_PKEY* key = EVP_PKEY_new();
	BIGNUM* bn = BN_new();
	RSA* rsa = RSA_new();
	if (!key || !bn || !rsa)
		goto _failed;

	if (BN_set_word(bn, 0x10001) &&
			RSA_generate_key_ex(rsa, key_len, bn, NULL) &&
			EVP_PKEY_assign_RSA(key, rsa)) {
		BN_free(bn);
		return key;
	}

_failed:
	if (rsa)
		RSA_free(rsa);
	if (bn)
		BN_free(bn);
	if (key)
		EVP_PKEY_free(key);
	return NULL;
}

void pcs_free_pkey(EVP_PKEY *pkey)
{
	EVP_PKEY_free(pkey);
}

void pcs_print_cert(int log_level, X509* c)
{
	char *buff = NULL;
	BIO* tmp = BIO_new(BIO_s_mem());
	CHECK_ALLOC(tmp);
	X509_print_ex(tmp, c, XN_FLAG_SEP_CPLUS_SPC, 0);
	BIO_write(tmp, "\0", 1);
	BIO_get_mem_data(tmp, &buff);
	BUG_ON(!buff);
	pcs_log(log_level, "%s", buff);
	BIO_free(tmp);
}

char* pcs_cert_to_pem(X509 *c)
{
	char *buff = NULL;
	BIO* bio = BIO_new(BIO_s_mem());
	if (!bio)
		return NULL;
	if (!PEM_write_bio_X509(bio, c)) {
		pcs_ssl_print_error(LOG_ERR, "PEM_write_bio_X509 failed");
		BIO_free(bio);
		return NULL;
	}

	BIO_write(bio, "\0", 1);
	BIO_get_mem_data(bio, &buff);
	buff = pcs_strdup(buff);
	BIO_free(bio);
	return buff;
}

static const char *__pkey_pass = "CA certificate";

char * pcs_pkey_to_pem(EVP_PKEY *key)
{
	char *buff = NULL;
	BIO* bio = BIO_new(BIO_s_mem());
	if (!bio)
		return NULL;

	if (!PEM_write_bio_PrivateKey(bio, key, EVP_des_ede3_cbc(),
			NULL, 0, 0, (void*)__pkey_pass)) {
		pcs_ssl_print_error(LOG_ERR, "PEM_write_bio_PrivateKey failed");
		BIO_free(bio);
		return NULL;
	}

	BIO_write(bio, "\0", 1);
	BIO_get_mem_data(bio, &buff);
	buff = pcs_strdup(buff);
	BIO_free(bio);
	return buff;
}

static int read_pem_file(const char *path, char **res)
{
	int r;
	pcs_fd_t fd = PCS_INVALID_FD;
	struct pcs_stat stat;
	char *buf = NULL;

	if ((r = pcs_sync_open(path, O_RDONLY, 0, &fd))) {
		r = -pcs_errno_to_err(-r);
		goto out;
	}
	if ((r = pcs_sync_fstat(fd, &stat))) {
		r = -pcs_errno_to_err(-r);
		goto out;
	}
	buf = pcs_xmalloc(stat.size + 1);
	r = pcs_sync_nread(fd, 0, buf, stat.size);
	if (r < 0) {
		r = -pcs_errno_to_err(-r);
		goto out;
	}
	if (r < stat.size) {
		pcs_log(LOG_ERR, "read('%s', 0, %llu) returned %i", path, (llu)stat.size, r);
		r = -PCS_ERR_INVALID;
		goto out;
	}
	buf[r] = '\0';
	r = 0;
out:
	if (r < 0)
		pcs_free(buf);
	else
		(*res) = buf;

	if (fd != PCS_INVALID_FD)
		pcs_sync_close(fd);
	return r;
}

X509* pcs_cert_from_pem(const char *pem, int *out_sz)
{
	char *tmp;
	X509 *c = NULL;
	int len = (int)strlen(pem);
	BIO* bio = BIO_new_mem_buf((void*)pem, len);
	if (!bio)
		return NULL;
	BIO_set_mem_eof_return(bio, 0);
	BIO_set_flags(bio, BIO_FLAGS_MEM_RDONLY);
	c = PEM_read_bio_X509(bio, NULL, NULL, "\0");
	*out_sz = len - BIO_get_mem_data(bio, &tmp);
	BIO_free(bio);
	return c;
}

int pcs_cert_from_pem_file(const char *path, X509 **res)
{
	int r;

	char *pem = NULL;
	if ((r = read_pem_file(path, &pem)))
		return r;
	int out_sz;
	X509 *c = pcs_cert_from_pem(pem, &out_sz);
	pcs_free(pem);

	if (c == NULL)
		return -PCS_ERR_INVALID;
	(*res) = c;
	return 0;
}

EVP_PKEY *pcs_pkey_from_pem(const char *pem, int *out_sz)
{
	EVP_PKEY *key = NULL;
	char *tmp;
	int len = (int)strlen(pem);
	BIO* bio = BIO_new_mem_buf((void*)pem, len);
	if (!bio)
		return NULL;
	BIO_set_mem_eof_return(bio, 0);
	BIO_set_flags(bio, BIO_FLAGS_MEM_RDONLY);
	key = PEM_read_bio_PrivateKey(bio, NULL, 0, (void*)__pkey_pass);
	*out_sz = len - BIO_get_mem_data(bio, &tmp);
	BIO_free(bio);
	return key;
}

int pcs_pkey_from_pem_file(const char *path, EVP_PKEY **res)
{
	int r;

	char *pem = NULL;
	if ((r = read_pem_file(path, &pem)))
		return r;
	int out_sz;
	EVP_PKEY *key = pcs_pkey_from_pem(pem, &out_sz);
	pcs_free(pem);

	if (key == NULL)
		return -PCS_ERR_INVALID;
	(*res) = key;
	return 0;
}

X509_CRL* pcs_crl_from_pem(const char *pem, int *out_sz)
{
	X509_CRL *crl = NULL;
	char *tmp;
	int len = (int)strlen(pem);
	BIO* bio = BIO_new_mem_buf((void*)pem, len);
	if (!bio)
		return NULL;
	BIO_set_mem_eof_return(bio, 0);
	BIO_set_flags(bio, BIO_FLAGS_MEM_RDONLY);
	crl = PEM_read_bio_X509_CRL(bio, NULL, 0, NULL);
	*out_sz = len - BIO_get_mem_data(bio, &tmp);
	BIO_free(bio);
	return crl;
}

int pcs_crl_from_pem_file(const char *path, X509_CRL **res)
{
	int r;

	char *pem = NULL;
	if ((r = read_pem_file(path, &pem)))
		return r;
	int out_sz;
	X509_CRL *crl = pcs_crl_from_pem(pem, &out_sz);
	pcs_free(pem);

	if (crl == NULL)
		return -PCS_ERR_INVALID;
	(*res) = crl;
	return 0;
}

X509* pcs_create_cert(EVP_PKEY *key, const unsigned char *cn)
{
	ASN1_INTEGER* cert_serial;
	X509* cert = NULL;
	BIGNUM* serial = NULL;
	X509_NAME* cert_name = NULL;

	cert = X509_new();
	if (!cert ||
			!(cert_serial = X509_get_serialNumber(cert)) ||
			!(cert_name = X509_get_subject_name(cert))) {
		pcs_log(LOG_ERR, "Can't allocate certificate");
		goto _failed;
	}

	if (!X509_set_pubkey(cert, key) ||
			!X509_set_version(cert, 1)) {
		pcs_log(LOG_ERR, "Unable initialize certificate");
		goto _failed;
	}

	/* set lifetime */
	if (!X509_gmtime_adj(X509_get_notBefore(cert), 0) ||
			!X509_gmtime_adj(X509_get_notAfter(cert), LIFETIME)) {
		pcs_log(LOG_ERR, "Unable set lifetime for certificate");
		goto _failed;
	}

	/* set common name */
	if (!X509_NAME_add_entry_by_txt(cert_name,"CN", MBSTRING_ASC, cn, -1, -1, 0) ||
			!X509_set_issuer_name(cert,cert_name)) {
		pcs_log(LOG_ERR, "Unable set common name for certificate");
		goto _failed;
	}

	serial = BN_new();
	if (!serial || !BN_pseudo_rand(serial, 64, 0, 0) ||
			!BN_to_ASN1_INTEGER(serial, cert_serial)) {

		pcs_log(LOG_ERR, "Unable set serial for certificate");
		BN_free(serial);
		goto _failed;
	}

	BN_free(serial);
	if (X509_sign(cert, key, EVP_sha256()))
		return cert;

	pcs_log(LOG_ERR, "Can' sign certificate");
_failed:
	if (cert)
		X509_free(cert);

	return NULL;
}

void pcs_free_cert(X509 *cert)
{
	X509_free(cert);
}

void pcs_free_crl(X509_CRL *crl)
{
	X509_CRL_free(crl);
}

void pcs_ssl_print_error(int log_lvl, const char *msg)
{
        char err_buf[512];
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        pcs_log(log_lvl, "%s: %s", msg, err_buf);
}

int base64_encode(const char *input, int input_len, char *out, int outl)
{
	BIO *bmem, *b64;
	BUF_MEM *ptr = NULL;
	int res = -1;

	b64 = BIO_new(BIO_f_base64());
	CHECK_ALLOC(b64);

	bmem = BIO_new(BIO_s_mem());
	CHECK_ALLOC(bmem);

	b64 = BIO_push(b64, bmem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	if (BIO_write(b64, input, input_len) != input_len)
		goto _cleanup;

	(void)BIO_flush(b64);
	BIO_get_mem_ptr(b64, &ptr);

	if (ptr->length < outl)
		res = (int)ptr->length;
	else
		res = outl;

	memcpy(out, ptr->data, res);
_cleanup:
	BIO_free_all(b64);

	return res;
}

int base64_decode(const char *input, int len, unsigned char *out)
{
	BIO *b64, *bmem;
	int outlen = 0;

	memset(out, 0, len);

	b64 = BIO_new(BIO_f_base64());
	CHECK_ALLOC(b64);

	bmem = BIO_new_mem_buf((void*)input, -1);
	CHECK_ALLOC(bmem);
	bmem = BIO_push(b64, bmem);
	BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

	outlen = BIO_read(bmem, out, len);
	if (outlen < 0 || outlen > len)
		outlen = -1;

	BIO_free_all(bmem);
	return outlen;
}
