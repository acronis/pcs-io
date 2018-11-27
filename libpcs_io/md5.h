/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

/*
 * This is the header file for the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * pcs_md5_context structure, pass it to pcs_md5_init, call pcs_md5_update as
 * needed on buffers full of bytes, and then call pcs_md5_final, which
 * will fill a supplied 16-byte array with the digest.
 *
 */

#ifndef MD5_H
#define MD5_H

#include "pcs_types.h"

#define MD5_LEN	16

struct pcs_md5_context {
	u32 buf[4];
	u32 bytes[2];
	u32 in[MD5_LEN];
};

void pcs_md5_init(struct pcs_md5_context *context);
void pcs_md5_update(struct pcs_md5_context *context, const void *buf, unsigned len);
void pcs_md5_final(unsigned char digest[MD5_LEN], struct pcs_md5_context *context);

static inline void pcs_md5_hash(unsigned char digest[MD5_LEN], const void *buf, unsigned len)
{
	struct pcs_md5_context c;

	pcs_md5_init(&c);
	pcs_md5_update(&c, buf, len);
	pcs_md5_final(digest, &c);
}

#endif /* !MD5_H */
