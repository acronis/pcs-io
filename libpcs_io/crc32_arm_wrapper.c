/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include <string.h>
#include "crc32.h"
#include "pcs_endian.h"
#include "pcs_align.h"
#include "bug.h"

#ifdef HAVE_CRC32_ARM

int crc32_use_arm = USE_NEON | USE_ARM_CRC;

/*
 * len - sizeof buffer (multiple of 16 bytes), len should be > 63
 */
unsigned int crc32c_pmull_le(const unsigned char* buf, unsigned int len, unsigned crc);

/*
 * len - sizeof buffer (any)
 */
unsigned int crc32c_armv8_le(unsigned int init_crc, const unsigned char* buf, unsigned int len);
unsigned int crc32c_armv8_be(unsigned int init_crc, const unsigned char* buf, unsigned int len);


inline unsigned int crc32up_neon_pmull_le(unsigned int crc, const unsigned char *s, unsigned int len)
{
	unsigned char tmp[68];
	unsigned int tail = len % 64;
	unsigned int len64 = len - tail;
	unsigned int tcrc;

	crc ^= 0xffffffff;

	if (len64)
		crc = crc32c_pmull_le(s, len64, crc);

	if (tail) {
		tcrc = crc;
		memset(tmp, 0, sizeof(tmp));
		memcpy(tmp + 64 - tail, s + len64, tail);
		*(unsigned int*) (tmp + 64 - tail) ^=  crc;
		crc = crc32c_pmull_le(tmp, 64, 0);

		if (tail < 4)
			crc ^= tcrc >> (8 * tail);
	}

	crc ^= 0xffffffff;

	return crc;
}

inline unsigned int crc32_neon_pmull_le(const unsigned char *s, unsigned int len)
{
	return crc32up_neon_pmull_le(0, s, len);
}

inline unsigned int crc32up_arm_crc(unsigned int crc, const unsigned char *s, unsigned int len)
{
	crc ^= 0xffffffff;

#ifdef __ARM_ARCH_8A__
	unsigned char begin[4] __aligned(4) = {0};
	unsigned int shift = ((unsigned long) s) & 3;
	unsigned int pref;

	if (shift) {
		pref = 4 - shift;
		memcpy(begin, s, sizeof(begin));
		len -= pref;

		crc = pcs_cpu_little_endian()
			? crc32c_armv8_le(crc, begin, pref)
			: crc32c_armv8_be(crc, begin, pref);
	}

	if (len)
#endif /* __ARM_ARCH_8A__ */
		crc = pcs_cpu_little_endian()
			? crc32c_armv8_le(crc, s, len)
			: crc32c_armv8_be(crc, s, len);

	crc ^= 0xffffffff;
	return crc;
}

inline unsigned int crc32_arm_crc(const unsigned char *s, unsigned int len)
{
	return crc32up_arm_crc(0, s, len);
}

#endif /* HAVE_CRC32_ARM */
