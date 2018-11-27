/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include <stdlib.h>
#include <stdint.h>
#include "adler32.h"

#define BASE 65521L /* largest prime smaller than 65536 */
#define NMAX 5552
/* NMAX is the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1 */

#define DO1(buf,i)  {s1 += buf[i]; s2 += s1;}
#define DO2(buf,i)  DO1(buf,i); DO1(buf,i+1);
#define DO4(buf,i)  DO2(buf,i); DO2(buf,i+2);
#define DO8(buf,i)  DO4(buf,i); DO4(buf,i+4);
#define DO16(buf)   DO8(buf,0); DO8(buf,8);

unsigned int zlib_adler32(unsigned int adler, const unsigned char *buf, unsigned int len)
{
	unsigned long s1 = adler & 0xffff;
	unsigned long s2 = (adler >> 16) & 0xffff;
	int k;

	if (buf == NULL)
		return 1;

	while (len > 0) {
		k = len < NMAX ? len : NMAX;
		len -= k;
		while (k >= 16) {
			DO16(buf);
			buf += 16;
			k -= 16;
		}
		if (k != 0) do {
			s1 += *buf++;
			s2 += s1;
		} while (--k);
		s1 %= BASE;
		s2 %= BASE;
	}
	return (s2 << 16) | s1;
}

unsigned int fast_adler32(unsigned int initial, const unsigned char* buf, unsigned int size)
{
	const uint32_t n = 1;
	size_t len = size;
	size_t s1 = initial & 0xffff;
	size_t s2 = initial >> 16;
	unsigned i;

	if (sizeof(void *) == 8) {
		while (((size_t)buf & 7) && len)
		{
			s1 += *(buf++);
			s2 += s1;
			len--;
		}

		while (len >= 23 * 8) {
			len -= 23 * 8;
			s2 += s1 * 23 * 8;

			uint64_t a1 = 0;
			uint64_t a2 = 0;
			uint64_t b1 = 0;
			uint64_t b2 = 0;

			for (i = 0; i < 23; ++i) {
				uint64_t v = *(uint64_t*)buf;
				a2 += a1;
				b2 += b1;
				a1 +=  v & 0x00FF00FF00FF00FF;
				b1 += (v >> 8) & 0x00FF00FF00FF00FF;
				buf += 8;
			}

			s1 += (((a1 + b1) * 0x1000100010001) >> 48);
			s2 += ((((a2 & 0xFFFF0000FFFF) + (b2 & 0xFFFF0000FFFF) + ((a2 >> 16) & 0xFFFF0000FFFF) + ((b2 >> 16) & 0xFFFF0000FFFF)) * 0x800000008) >> 32);
			if (*(char *)&n)	/* little endian */
				s2 += 2 * ((a1 * 0x4000300020001) >> 48) + ((b1 * 0x1000100010001) >> 48) + 2 * ((b1 * 0x3000200010000) >> 48);
			else			/* big endian */
				s2 += 2 * ((b1 * 0x1000200030004) >> 48) + ((a1 * 0x1000100010001) >> 48) + 2 * ((a1 * 0x0000100020003) >> 48);

			s1 %= BASE;
			s2 %= BASE;
		}
	} else {
		/* non-64bit system */
		while (len >= NMAX) {
			len -= NMAX;

			for (i = 0; i < NMAX; ++i) {
				s1 += *(buf++);
				s2 += s1;
			}

			s1 %= BASE;
			s2 %= BASE;
		}
	}

	while (len) {
		s1 += *(buf++);
		s2 += s1;
		len--;
	}

	s1 %= BASE;
	s2 %= BASE;

	return (unsigned int)((s2 << 16) | s1);
}
