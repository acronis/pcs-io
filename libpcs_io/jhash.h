#ifndef _PCS_JHASH_H_
#define _PCS_JHASH_H_ 1

#include "pcs_types.h"

/*
http://www.burtleburtle.net/bob/c/lookup2.c
--------------------------------------------------------------------
lookup2.c, by Bob Jenkins, December 1996, Public Domain.
--------------------------------------------------------------------
*/

#define jmix(a,b,c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8);  \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12); \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5);  \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

/* the golden ratio; an arbitrary value */
#define JHASH_MAGIC 0x9e3779b9

static inline u32 jhash2(
	u32 const* k, /* the key */
	u32 length,   /* the length of the key, in u32s */
	u32 initval   /* the previous hash, or an arbitrary value */
) {
	register u32 a,b,c,len;

	/* Set up the internal state */
	len = length;
	a = b = JHASH_MAGIC;  /* the golden ratio; an arbitrary value */
	c = initval;          /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 3)
	{
		a += k[0];
		b += k[1];
		c += k[2];
		jmix(a,b,c);
		k += 3; len -= 3;
	}

	/*-------------------------------------- handle the last 2 ub4's */
	c += (length<<2);
	switch(len)              /* all the case statements fall through */
	{
		/* c is reserved for the length */
		case 2 : b+=k[1]; /* FALLTHROUGH */
		case 1 : a+=k[0];
		/* case 0: nothing left to add */
	}
	jmix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}

/* This is special version of lookup2, handling hashing of 3 u32 words only. */
static inline u32 jhash3(u32 a, u32 b, u32 c, u32 initval)
{
	a += JHASH_MAGIC;
	b += JHASH_MAGIC;
	c += initval;
	jmix(a, b, c);
	return c;
}

#endif /* _PCS_JHASH_H_ */
