/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#pragma once

static inline u64 next_pow2(u32 x)
{
	if (x <= 2) return x;
	return (1ULL << 32) >> __builtin_clz(x - 1);
}

static inline s32 _log2(u32 x)
{
	if (x <= 2) return (s32)x - 1;
	return 8 * sizeof(x) - 1 - __builtin_clz(x);
}

static inline s32 _log2l(u64 x)
{
	if (x <= 2) return (s32)x - 1;
	return 8 * sizeof(x) - 1 - __builtin_clzl(x);
}

/* Calculate a * b / c avoiding overflow */
static inline u64 muldiv_safe(u64 a, u64 b, u64 c)
{
	u64 v;
	/* The arithmetic width */
	s32 const w = 8 * sizeof(v), hw = w / 2;
	/* How many bits are occupied by operands */
	s32 a_ = 1 + _log2l(a), b_ = 1 + _log2l(b), c_, x_;
	if (a_ + b_ <= w)
		/* No overflow, trivial case */
		return a * b / c;
	c_ = 1 + _log2l(c);
	if (a_ + b_ - c_ > w)
		/* Result overflow, returns max representable value */
		return ~0UL;
	/* How many excessive bits the a*b has */
	x_ = a_ + b_ - w;
	/* Right shift a, b operands so a*b will occupy exactly w bits.
	 * Note that we are loosing at most 2^-hw of precision here.
	 */
	if (a_ > hw) {
		if (b_ > hw) {
			a >>= (a_ - hw);
			b >>= (b_ - hw);
		} else {
			a >>= x_;
		}
	} else {
		b >>= x_;
	}
	/* Now we can safely multiply. The result will occupy exactly w bits. */
	v = a * b;
	if (c_ > hw) {
		/* Right shift c to hw bits so the reminder will occupy hw bits as well.
		 * So we are loosing at most 2^-hw of precision on deletion.
		 */
		s32 sht = c_ - hw;
		if (sht > x_)
			sht = x_;
		c >>= sht;
		x_ -= sht;
	}
	/* Calculate the ultimate result */
	return (v / c) << x_;
}
