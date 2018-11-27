/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "lz4_estimate.h"
#include "pcs_endian.h"
#include "bug.h"

#include <string.h>
#include <limits.h> /* might define __WORDSIZE */


#define MIN(a, b)	((a) < (b) ? (a) : (b))

#define HASH_LOG	12
#define SKIP_TRIGGER	6
#define MAX_DISTANCE	(1u << 15)
#define MIN_MATCH	4


#ifdef _WIN64
#define BITS64	1
#elif defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ == 8
#define BITS64	1
#elif defined(__WORDSIZE) && __WORDSIZE == 64
#define BITS64	1
#endif

#ifdef _MSC_VER
#ifdef BITS64
unsigned char _BitScanForward64(unsigned long *, unsigned __int64);
#pragma intrinsic(_BitScanForward64)

unsigned char _BitScanReverse64(unsigned long *, unsigned __int64);
#pragma intrinsic(_BitScanReverse64)
#else
unsigned char _BitScanForward(unsigned long *, unsigned long);
#pragma intrinsic(_BitScanForward)
unsigned char _BitScanReverse(unsigned long *, unsigned long);
#pragma intrinsic(_BitScanReverse)
#endif /* BITS64 */
#endif /* _MSC_VER */

static inline int zero_bits(size_t val)
{
#ifdef _MSC_VER
	unsigned long result;
#if __BYTE_ORDER == __LITTLE_ENDIAN
#ifdef BITS64
	_BitScanForward64(&result, val);
#else
	_BitScanForward(&result, val);
#endif
#else
#ifdef BITS64
	_BitScanReverse64(&result, val);
#else
	_BitScanReverse(&result, val);
#endif
#endif
	return (int)result;
#else /* _MSC_VER */
#if __BYTE_ORDER == __LITTLE_EDNIAN
#ifdef BITS64
	return __builtin_ctzll(val);
#else
	return __builtin_ctz(val);
#endif /* BITS64 */
#else
#ifdef BITS64
	return __builtin_clzll(val);
#else
	return __builtin_clz(val);
#endif /* BITS64 */
#endif /* __BYTE_ORDER */
#endif
}

static inline unsigned hash(size_t sequence)
{
#ifdef BITS64
	return ((sequence * 889523592379ull) >> (40 - HASH_LOG)) & ((1u << HASH_LOG) - 1);
#else
	return (sequence * 2654435761u) >> (32 - HASH_LOG);
#endif
}

static inline size_t read_arch(const char *p)
{
	return pcs_get_unaligned_ptr(p);
}

static inline unsigned read32(const char *p)
{
	return pcs_get_unaligned_32(p);
}

static inline unsigned hash_pos(const void *p)
{
	return hash(read_arch(p));
}

#ifdef BITS64
typedef unsigned hash_table_t;

static inline void put_table(const char *p, unsigned h, hash_table_t *table, const char *src)
{
	table[h] = (unsigned)(p - src);
}

static inline const char *get_table(unsigned h, hash_table_t *table, const char *src)
{
	return src + table[h];
}
#else
typedef const char* hash_table_t;

static inline void put_table(const char *p, unsigned h, hash_table_t *table, const char *src)
{
	(void)src;
	table[h] = p;
}

static inline const char *get_table(unsigned h, hash_table_t *table, const char *src)
{
	(void)src;
	return table[h];
}
#endif

static inline void put_pos(const char *p, hash_table_t *table, const char *src)
{
	put_table(p, hash_pos(p), table, src);
}

static inline const char *get_pos(const char *p, hash_table_t *table, const char *src)
{
	return get_table(hash_pos(p), table, src);
}

/* Returns how much bytes compressed data is less than original data. limit parameter
 * allows early return, that is if current estimated value is greater than limit
 * function returns whithout looking at whole data. */
/* NOTE: it's quite rough estimation, so it's only usefull as a data compressibility test. */
static size_t lz4_compression_effect(const char *buf, size_t buf_len, size_t limit)
{
	if (buf_len <= sizeof(size_t))
		return 0;

	hash_table_t table[1 << HASH_LOG] = { 0 };
	const char *input = buf;
	const char *end = buf + buf_len - sizeof(size_t);
	size_t result = 0;

	put_pos(input, table, buf);

	for (;;) {
		const char *match;
		const char *anchor = input;
		size_t count = 0;

		for (;;) {
			if (++input > end)
				return MIN(result, buf_len);

			match = get_pos(input, table, buf);
			put_pos(input, table, buf);

			if (match + MAX_DISTANCE >= input && read32(match) == read32(input))
				break;

			input += (++count >> SKIP_TRIGGER);
		}

		const char *input_back = input;
		const char *match_back = match;

		while (input_back > anchor && match_back > buf && *(--input_back) == *(--match_back))
			++result;

		do {
			input += MIN_MATCH;
			match += MIN_MATCH;
			result += MIN_MATCH - 3;

			/* count match length */
			for (;;) {
				if (input > end)
					return MIN(result, buf_len);

				const size_t diff = read_arch(match) ^ read_arch(input);

				if (diff) {
					const int equal = zero_bits(diff) >> 3;

					input += equal;
					result += equal;
					break;
				}

				input += sizeof(size_t);
				match += sizeof(size_t);
				result += sizeof(size_t);
			}

			if (input > end || result >= limit)
				return MIN(result, buf_len);
	
			match = get_pos(input, table, buf);
			put_pos(input, table, buf);
		} while (match + MAX_DISTANCE >= input && read32(match) == read32(input));
	}
}

size_t lz4_compressed_size_estimate(const char *buf, size_t buf_len)
{
	const size_t eaten = lz4_compression_effect(buf, buf_len, ~(size_t)0);

	return buf_len - eaten;
}

int lz4_data_compressible(const char *buf, size_t buf_len, double ratio)
{
	const size_t threshold = (size_t)(buf_len * ratio);
	const size_t eaten = lz4_compression_effect(buf, buf_len, threshold);

	return eaten >= threshold ? 1 : 0;
}
