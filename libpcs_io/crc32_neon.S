/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifdef __aarch64__

	.text
	.cpu		generic+crypto+crc

.Lcrc32_constants:
	/*
	 * [x4*128+32 mod P(x) << 32)]'  << 1   = 0x154442bd4
	 * #define CONSTANT_R1  0x154442bd4LL
	 *
	 * [(x4*128-32 mod P(x) << 32)]' << 1   = 0x1c6e41596
	 * #define CONSTANT_R2  0x1c6e41596LL
	 */
	.octa		0x00000001c6e415960000000154442bd4

	/*
	 * [(x128+32 mod P(x) << 32)]'   << 1   = 0x1751997d0
	 * #define CONSTANT_R3  0x1751997d0LL
	 *
	 * [(x128-32 mod P(x) << 32)]'   << 1   = 0x0ccaa009e
	 * #define CONSTANT_R4  0x0ccaa009eLL
	 */
	.octa		0x00000000ccaa009e00000001751997d0

	/*
	 * [(x64 mod P(x) << 32)]'       << 1   = 0x163cd6124
	 * #define CONSTANT_R5  0x163cd6124LL
	 */
	.quad		0x0000000163cd6124
	.quad		0x00000000FFFFFFFF

	/*
	 * #define CRCPOLY_TRUE_LE_FULL 0x1DB710641LL
	 *
	 * Barrett Reduction constant (u64`) = u` = (x**64 / P(x))`
	 *                                                      = 0x1F7011641LL
	 * #define CONSTANT_RU  0x1F7011641LL
	 */
	.octa		0x00000001F701164100000001DB710641

.Lcrc32c_constants:
	.octa		0x000000009e4addf800000000740eef02
	.octa		0x000000014cd00bd600000000f20c0dfe
	.quad		0x00000000dd45aab8
	.quad		0x00000000FFFFFFFF
	.octa		0x00000000dea713f10000000105ec76f0

	vCONSTANT	.req	v0
	dCONSTANT	.req	d0
	qCONSTANT	.req	q0

	BUF		.req	x0
	LEN		.req	x1
	CRC		.req	x2

	vzr		.req	v9

	/**
	 * Calculate crc32
	 * BUF - buffer
	 * LEN - sizeof buffer (multiple of 16 bytes), LEN should be > 63
	 * CRC - initial crc32
	 * return %eax crc32
	 * uint crc32_pmull_le(unsigned char const *buffer,size_t len, uint crc32)
	 */
	.global crc32_pmull_le
crc32_pmull_le:
	adr		x3, .Lcrc32_constants
	b		0f

	.global crc32c_pmull_le
crc32c_pmull_le:
	adr		x3, .Lcrc32c_constants

0:	bic		LEN, LEN, #15
	ld1		{v1.16b-v4.16b}, [BUF], #0x40
	movi		vzr.16b, #0
	fmov		dCONSTANT, CRC
	eor		v1.16b, v1.16b, vCONSTANT.16b
	sub		LEN, LEN, #0x40
	cmp		LEN, #0x40
	b.lt		less_64

	ldr		qCONSTANT, [x3]

loop_64:		/* 64 bytes Full cache line folding */
	sub		LEN, LEN, #0x40

	pmull2		v5.1q, v1.2d, vCONSTANT.2d
	pmull2		v6.1q, v2.2d, vCONSTANT.2d
	pmull2		v7.1q, v3.2d, vCONSTANT.2d
	pmull2		v8.1q, v4.2d, vCONSTANT.2d

	pmull		v1.1q, v1.1d, vCONSTANT.1d
	pmull		v2.1q, v2.1d, vCONSTANT.1d
	pmull		v3.1q, v3.1d, vCONSTANT.1d
	pmull		v4.1q, v4.1d, vCONSTANT.1d

	eor		v1.16b, v1.16b, v5.16b
	ld1		{v5.16b}, [BUF], #0x10
	eor		v2.16b, v2.16b, v6.16b
	ld1		{v6.16b}, [BUF], #0x10
	eor		v3.16b, v3.16b, v7.16b
	ld1		{v7.16b}, [BUF], #0x10
	eor		v4.16b, v4.16b, v8.16b
	ld1		{v8.16b}, [BUF], #0x10

	eor		v1.16b, v1.16b, v5.16b
	eor		v2.16b, v2.16b, v6.16b
	eor		v3.16b, v3.16b, v7.16b
	eor		v4.16b, v4.16b, v8.16b

	cmp		LEN, #0x40
	b.ge		loop_64

less_64:		/* Folding cache line into 128bit */
	ldr		qCONSTANT, [x3, #16]

	pmull2		v5.1q, v1.2d, vCONSTANT.2d
	pmull		v1.1q, v1.1d, vCONSTANT.1d
	eor		v1.16b, v1.16b, v5.16b
	eor		v1.16b, v1.16b, v2.16b

	pmull2		v5.1q, v1.2d, vCONSTANT.2d
	pmull		v1.1q, v1.1d, vCONSTANT.1d
	eor		v1.16b, v1.16b, v5.16b
	eor		v1.16b, v1.16b, v3.16b

	pmull2		v5.1q, v1.2d, vCONSTANT.2d
	pmull		v1.1q, v1.1d, vCONSTANT.1d
	eor		v1.16b, v1.16b, v5.16b
	eor		v1.16b, v1.16b, v4.16b

	cbz		LEN, fold_64

loop_16:		/* Folding rest buffer into 128bit */
	subs		LEN, LEN, #0x10

	ld1		{v2.16b}, [BUF], #0x10
	pmull2		v5.1q, v1.2d, vCONSTANT.2d
	pmull		v1.1q, v1.1d, vCONSTANT.1d
	eor		v1.16b, v1.16b, v5.16b
	eor		v1.16b, v1.16b, v2.16b

	b.ne		loop_16

fold_64:
	/* perform the last 64 bit fold, also adds 32 zeroes
	 * to the input stream */
	ext		v2.16b, v1.16b, v1.16b, #8
	pmull2		v2.1q, v2.2d, vCONSTANT.2d
	ext		v1.16b, v1.16b, vzr.16b, #8
	eor		v1.16b, v1.16b, v2.16b

	/* final 32-bit fold */
	ldr		dCONSTANT, [x3, #32]
	ldr		d3, [x3, #40]

	ext		v2.16b, v1.16b, vzr.16b, #4
	and		v1.16b, v1.16b, v3.16b
	pmull		v1.1q, v1.1d, vCONSTANT.1d
	eor		v1.16b, v1.16b, v2.16b

	/* Finish up with the bit-reversed barrett reduction 64 ==> 32 bits */
	ldr		qCONSTANT, [x3, #48]

	and		v2.16b, v1.16b, v3.16b
	ext		v2.16b, vzr.16b, v2.16b, #8
	pmull2		v2.1q, v2.2d, vCONSTANT.2d
	and		v2.16b, v2.16b, v3.16b
	pmull		v2.1q, v2.1d, vCONSTANT.1d
	eor		v1.16b, v1.16b, v2.16b
	mov		w0, v1.s[1]

	ret


	/**
	 * calculate crc32-c using arm crc32c instruction
	 * uint crc32_armv8_le(u32 init_crc, const u8 buf[], size_t len);
	 */

	.macro		__crc32c, en
0:	subs		x2, x2, #16
	b.mi		8f
	ldp		x3, x4, [x1], #16
	\en\()		x3, x3
	\en\()		x4, x4
	crc32cx		w0, w0, x3
	crc32cx		w0, w0, x4
	b.ne		0b
	b		0f

8:	tbz		x2, #3, 4f
	ldr		x3, [x1], #8
	\en\()		x3, x3
	crc32cx		w0, w0, x3
4:	tbz		x2, #2, 2f
	ldr		w3, [x1], #4
	\en\()		w3, w3
	crc32cw		w0, w0, w3
2:	tbz		x2, #1, 1f
	ldrh		w3, [x1], #2
	\en\()16	w3, w3
	crc32ch		w0, w0, w3
1:	tbz		x2, #0, 0f
	ldrb		w3, [x1]
	crc32cb		w0, w0, w3
0:
	ret
	.endm

	.global		crc32c_armv8_le
crc32c_armv8_le:
	__crc32c	#

	.global		crc32c_armv8_be
crc32c_armv8_be:
	__crc32c	rev

#elif defined(__ARM_ARCH_8A__)

	.align		6
	.arch		armv8-a
	.arch_extension	crc
	.fpu		crypto-neon-fp-armv8

.Lcrc32_constants:
	/*
	 * [x4*128+32 mod P(x) << 32)]'  << 1   = 0x154442bd4
	 * #define CONSTANT_R1  0x154442bd4LL
	 *
	 * [(x4*128-32 mod P(x) << 32)]' << 1   = 0x1c6e41596
	 * #define CONSTANT_R2  0x1c6e41596LL
	 */
	.quad		0x0000000154442bd4
	.quad		0x00000001c6e41596

	/*
	 * [(x128+32 mod P(x) << 32)]'   << 1   = 0x1751997d0
	 * #define CONSTANT_R3  0x1751997d0LL
	 *
	 * [(x128-32 mod P(x) << 32)]'   << 1   = 0x0ccaa009e
	 * #define CONSTANT_R4  0x0ccaa009eLL
	 */
	.quad		0x00000001751997d0
	.quad		0x00000000ccaa009e

	/*
	 * [(x64 mod P(x) << 32)]'       << 1   = 0x163cd6124
	 * #define CONSTANT_R5  0x163cd6124LL
	 */
	.quad		0x0000000163cd6124
	.quad		0x00000000FFFFFFFF

	/*
	 * #define CRCPOLY_TRUE_LE_FULL 0x1DB710641LL
	 *
	 * Barrett Reduction constant (u64`) = u` = (x**64 / P(x))`
	 *                                                      = 0x1F7011641LL
	 * #define CONSTANT_RU  0x1F7011641LL
	 */
	.quad		0x00000001DB710641
	.quad		0x00000001F7011641

.Lcrc32c_constants:
	.quad		0x00000000740eef02
	.quad		0x000000009e4addf8
	.quad		0x00000000f20c0dfe
	.quad		0x000000014cd00bd6
	.quad		0x00000000dd45aab8
	.quad		0x00000000FFFFFFFF
	.quad		0x0000000105ec76f0
	.quad		0x00000000dea713f1

	dCONSTANTl	.req	d0
	dCONSTANTh	.req	d1
	qCONSTANT	.req	q0

	BUF		.req	r0
	LEN		.req	r1
	CRC		.req	r2

	qzr		.req	q9

	/**
	 * Calculate crc32
	 * BUF - buffer
	 * LEN - sizeof buffer (multiple of 16 bytes), LEN should be > 63
	 * CRC - initial crc32
	 * return %eax crc32
	 * uint crc32_pmull_le(unsigned char const *buffer,
	 *                     size_t len, uint crc32)
	 */

	.global crc32c_pmull_le
crc32c_pmull_le:
	adr		r3, .Lcrc32c_constants

0:	bic		LEN, LEN, #15
	vld1.8		{q1-q2}, [BUF, :128]!
	vld1.8		{q3-q4}, [BUF, :128]!
	vmov.i8		qzr, #0
	vmov.i8		qCONSTANT, #0
	vmov.32		dCONSTANTl[0], CRC
	veor.8		d2, d2, dCONSTANTl
	sub		LEN, LEN, #0x40
	cmp		LEN, #0x40
	blt		less_64

	vld1.64		{qCONSTANT}, [r3]

loop_64:		/* 64 bytes Full cache line folding */
	sub		LEN, LEN, #0x40

	vmull.p64	q5, d3, dCONSTANTh
	vmull.p64	q6, d5, dCONSTANTh
	vmull.p64	q7, d7, dCONSTANTh
	vmull.p64	q8, d9, dCONSTANTh

	vmull.p64	q1, d2, dCONSTANTl
	vmull.p64	q2, d4, dCONSTANTl
	vmull.p64	q3, d6, dCONSTANTl
	vmull.p64	q4, d8, dCONSTANTl

	veor.8		q1, q1, q5
	vld1.8		{q5}, [BUF, :128]!
	veor.8		q2, q2, q6
	vld1.8		{q6}, [BUF, :128]!
	veor.8		q3, q3, q7
	vld1.8		{q7}, [BUF, :128]!
	veor.8		q4, q4, q8
	vld1.8		{q8}, [BUF, :128]!

	veor.8		q1, q1, q5
	veor.8		q2, q2, q6
	veor.8		q3, q3, q7
	veor.8		q4, q4, q8

	cmp		LEN, #0x40
	bge		loop_64

less_64:		/* Folding cache line into 128bit */
	vldr		dCONSTANTl, [r3, #16]
	vldr		dCONSTANTh, [r3, #24]

	vmull.p64	q5, d3, dCONSTANTh
	vmull.p64	q1, d2, dCONSTANTl
	veor.8		q1, q1, q5
	veor.8		q1, q1, q2

	vmull.p64	q5, d3, dCONSTANTh
	vmull.p64	q1, d2, dCONSTANTl
	veor.8		q1, q1, q5
	veor.8		q1, q1, q3

	vmull.p64	q5, d3, dCONSTANTh
	vmull.p64	q1, d2, dCONSTANTl
	veor.8		q1, q1, q5
	veor.8		q1, q1, q4

	teq		LEN, #0
	beq		fold_64

loop_16:		/* Folding rest buffer into 128bit */
	subs		LEN, LEN, #0x10

	vld1.8		{q2}, [BUF, :128]!
	vmull.p64	q5, d3, dCONSTANTh
	vmull.p64	q1, d2, dCONSTANTl
	veor.8		q1, q1, q5
	veor.8		q1, q1, q2

	bne		loop_16

fold_64:
	/* perform the last 64 bit fold, also adds 32 zeroes
	 * to the input stream */
	vmull.p64	q2, d2, dCONSTANTh
	vext.8		q1, q1, qzr, #8
	veor.8		q1, q1, q2

	/* final 32-bit fold */
	vldr		dCONSTANTl, [r3, #32]
	vldr		d6, [r3, #40]
	vmov.i8		d7, #0

	vext.8		q2, q1, qzr, #4
	vand.8		d2, d2, d6
	vmull.p64	q1, d2, dCONSTANTl
	veor.8		q1, q1, q2

	/* Finish up with the bit-reversed barrett reduction 64 ==> 32 bits */
	vldr		dCONSTANTl, [r3, #48]
	vldr		dCONSTANTh, [r3, #56]

	vand.8		q2, q1, q3
	vext.8		q2, qzr, q2, #8
	vmull.p64	q2, d5, dCONSTANTh
	vand.8		q2, q2, q3
	vmull.p64	q2, d4, dCONSTANTl
	veor.8		q1, q1, q2
	vmov		r0, s5

	bx		lr


	/**
	 * calculate crc32-c using arm crc32c instruction
	 * uint crc32_armv8_le(u32 init_crc, const u8 buf[], size_t len);
	 */

	.macro		__crc32c, en, _
	subs		ip, r2, #8
	bmi		.Ltailc\_\()

	teq		ip, #0
.Laligned8c\_\():
	ldrd		r2, r3, [r1], #8
	\en\()		r2, r2
	\en\()		r3, r3
	crc32cw		r0, r0, r2
	crc32cw		r0, r0, r3
	bxeq		lr
	subs		ip, ip, #8
	bpl		.Laligned8c\_\()

.Ltailc\_\():
	tst		ip, #4
	beq		2f
	ldr		r3, [r1], #4
	\en\()		r3, r3
	crc32cw		r0, r0, r3

2:	tst		ip, #2
	beq		1f
	ldrh		r3, [r1], #2
	\en\()16	r3, r3
	crc32ch		r0, r0, r3

1:	tst		ip, #1
	bxeq		lr
	ldrb		r3, [r1]
	crc32cb		r0, r0, r3
	bx		lr

	.endm

	.align		5
	.global		crc32c_armv8_le
crc32c_armv8_le:
	__crc32c	#


	.align		5
	.global		crc32c_armv8_be
crc32c_armv8_be:
	__crc32c	rev, _

#endif
