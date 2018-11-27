/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCS_ENDIAN_H__
#define __PCS_ENDIAN_H__

#include "pcs_types.h"

/* ----- little endian / big endian ----- */

typedef u64 le64;
typedef u32 le32;
typedef u16 le16;
typedef u8 le8;

typedef u64 be64;
typedef u32 be32;
typedef u16 be16;
typedef u8 be8;

#if defined(__GLIBC__)		/* Linux, SPARC, etc. */
#include <endian.h>
#include <byteswap.h>
#elif defined(__MAC__) || defined(__WINDOWS__) || defined(__x86_64__)
/* define Mac and Windows as litle endian */
#define __LITTLE_ENDIAN	1234
#define __BIG_ENDIAN	4321
#define __BYTE_ORDER	__LITTLE_ENDIAN
#else
#error "unknown endianes"
#endif

#ifdef _MSC_VER
#include <stdlib.h>
#define bswap_16 _byteswap_ushort
#define bswap_32 _byteswap_ulong
#define bswap_64 _byteswap_uint64
#endif

#ifdef __MAC__
#define bswap_16 __builtin_bswap16
#define bswap_32 __builtin_bswap32
#define bswap_64 __builtin_bswap64
#endif

#ifdef __SUN__
#include <sys/byteorder.h>
#define bswap_16 BSWAP_16
#define bswap_32 BSWAP_32
#define bswap_64 BSWAP_64
#endif

#define bswap_none(x)	(x)

#if (defined(__GNUC__) || defined(__clang__)) && !defined(__cplusplus)
/* compile-time macro to verify that bswap_XXX() are called with correct argument type and expected bitness */
#define BSWAP_VERIFY(fn, x, sz) ((sizeof(x) == sz) ? fn(x) : (u8)sizeof(struct {char bswap_arg_size_mismatch[(sizeof(x) == sz) ? 1 : -1]; }))
#else
#define BSWAP_VERIFY(fn, x, sz)	fn(x)
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le8(x)	BSWAP_VERIFY(bswap_none, x, 1)
#define cpu_to_le16(x)	BSWAP_VERIFY(bswap_none, x, 2)
#define cpu_to_le32(x)	BSWAP_VERIFY(bswap_none, x, 4)
#define cpu_to_le64(x)	BSWAP_VERIFY(bswap_none, x, 8)
#define le8_to_cpu(x)	BSWAP_VERIFY(bswap_none, x, 1)
#define le16_to_cpu(x)	BSWAP_VERIFY(bswap_none, x, 2)
#define le32_to_cpu(x)	BSWAP_VERIFY(bswap_none, x, 4)
#define le64_to_cpu(x)	BSWAP_VERIFY(bswap_none, x, 8)

#define cpu_to_be8(x)	BSWAP_VERIFY(bswap_none, x, 1)
#define cpu_to_be16(x)	BSWAP_VERIFY(bswap_16,   x, 2)
#define cpu_to_be32(x)	BSWAP_VERIFY(bswap_32,   x, 4)
#define cpu_to_be64(x)	BSWAP_VERIFY(bswap_64,   x, 8)
#define be8_to_cpu(x)	BSWAP_VERIFY(bswap_none, x, 1)
#define be16_to_cpu(x)	BSWAP_VERIFY(bswap_16,   x, 2)
#define be32_to_cpu(x)	BSWAP_VERIFY(bswap_32,   x, 4)
#define be64_to_cpu(x)	BSWAP_VERIFY(bswap_64,   x, 8)
#else
#define cpu_to_le8(x)	BSWAP_VERIFY(bswap_none, x, 1)
#define cpu_to_le16(x)	BSWAP_VERIFY(bswap_16,   x, 2)
#define cpu_to_le32(x)	BSWAP_VERIFY(bswap_32,   x, 4)
#define cpu_to_le64(x)	BSWAP_VERIFY(bswap_64,   x, 8)
#define le8_to_cpu(x)	BSWAP_VERIFY(bswap_none, x, 1)
#define le16_to_cpu(x)	BSWAP_VERIFY(bswap_16,   x, 2)
#define le32_to_cpu(x)	BSWAP_VERIFY(bswap_32,   x, 4)
#define le64_to_cpu(x)	BSWAP_VERIFY(bswap_64,   x, 8)

#define cpu_to_be8(x)	BSWAP_VERIFY(bswap_none, x, 1)
#define cpu_to_be16(x)	BSWAP_VERIFY(bswap_none, x, 2)
#define cpu_to_be32(x)	BSWAP_VERIFY(bswap_none, x, 4)
#define cpu_to_be64(x)	BSWAP_VERIFY(bswap_none, x, 8)
#define be8_to_cpu(x)	BSWAP_VERIFY(bswap_none, x, 1)
#define be16_to_cpu(x)	BSWAP_VERIFY(bswap_none, x, 2)
#define be32_to_cpu(x)	BSWAP_VERIFY(bswap_none, x, 4)
#define be64_to_cpu(x)	BSWAP_VERIFY(bswap_none, x, 8)
#endif

static inline int pcs_cpu_little_endian(void)
{
	const uint64_t n = 1;
	return *(char *)&n;
}

#endif
