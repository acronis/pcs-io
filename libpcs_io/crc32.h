/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __CRC32_H__
#define __CRC32_H__

#include "pcs_types.h"
#include "pcs_config.h"	/* for GCC_VERSION */

PCS_API unsigned int pcs_crc32(const unsigned char *s, unsigned int len);
PCS_API unsigned int pcs_crc32up(unsigned int crc, const unsigned char *s, unsigned int len);

/* ----------------------------------- internal API -------------------------------- */

/*
 * Performance:
 * 64bit: about 1.5GB/sec, i7 2.3Ghz, close to 1.5GB/sec for crc64
 * 32bit: about 1.1GB/sec, i7 2.3Ghz
 * SSE (below): 22GB/sec
 * ARMv8 (below) 1.2GB/sec
 * NOTE: performance significantly depends on compiler and almost doubled for me with clang 2014 -> 2016
 */
unsigned int crc32up_generic(unsigned int crc, const unsigned char *s, unsigned int len);

extern uint32_t crc32_table[4][256];

/* not sure about exact gcc version, so put 4.4 from RHEL6 */
#if (defined(__x86_64__) && (defined(__clang__) || GCC_VERSION >= 40400)) || defined(_WIN64)

#define HAVE_CRC32_SSE

PCS_API extern int crc32_use_sse;

/* about 22GB/sec, i7 2.3Ghz */
unsigned int crc32up_sse(unsigned int crc, const unsigned char *s, unsigned int len);
unsigned int crc32_sse(const unsigned char *s, unsigned int len);

#elif defined(__aarch64__) || defined(__ARM_ARCH_8A__)

#define HAVE_CRC32_ARM

#define USE_NEON 1
#define USE_ARM_CRC 2

extern int crc32_use_arm;

/*
 * ARMv8:
 *   linux 32bit ~1250 MB/sec
 */
unsigned int crc32up_arm_crc(unsigned int crc, const unsigned char *s, unsigned int len);
unsigned int crc32_arm_crc(const unsigned char *s, unsigned int len);

unsigned int crc32up_neon_pmull_le(unsigned int crc, const unsigned char *s, unsigned int len);
unsigned int crc32_neon_pmull_le(const unsigned char *s, unsigned int len);

#endif

#endif /* __CRC32_H__ */
