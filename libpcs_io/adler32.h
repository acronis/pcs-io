/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __ADLER32_H__
#define __ADLER32_H__

/* 64bit version. ~6GB/sec on i7 2.3Ghz */
unsigned int fast_adler32(unsigned int initial, const unsigned char* buf, unsigned int size);

/* zlib version. just for testing. ~2GB/sec on i7 2.3Ghz */
unsigned int zlib_adler32(unsigned int adler, const unsigned char *buf, unsigned int len);

#endif
