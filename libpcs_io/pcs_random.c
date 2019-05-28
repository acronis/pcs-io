/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_random.h"
#include "pcs_sync_io.h"
#include "log.h"
#include "timer.h"

#ifndef __WINDOWS__
#include <unistd.h>
#else
#define SystemFunction036 NTAPI SystemFunction036
#include <NTSecAPI.h>
#undef SystemFunction036
#endif

/* Fill buffer with pseudo random content. Returns 0 on success and -1 otherwise */
int pcs_get_urandom(void *buf, int sz)
{
#ifndef __WINDOWS__
	pcs_fd_t fd;
	int ret = pcs_sync_open("/dev/urandom", O_RDONLY, 0, &fd);
	if (ret) {
		pcs_log_syserror(LOG_ERR, ret, "Unable open /dev/urandom");
		return -1;
	}
	ret = pcs_sync_sread(fd, buf, sz);
	pcs_sync_close(fd);
	if (ret < 0) {
		pcs_log_syserror(LOG_ERR, ret, "Can't read from /dev/urandom");
		return -1;
	}
	if (ret != sz) {
		pcs_log(LOG_ERR, "Truncated read from /dev/urandom");
		return -1;
	}
#else
	if (!RtlGenRandom(buf, sz)) {
		pcs_log(LOG_ERR, "RtlGenRandom failed");
		return -1;
	}
#endif
	return 0;
}

void pcs_srandomdev(struct pcs_rng *rng)
{
	if (!pcs_get_urandom(rng->data, sizeof(rng->data))) {
		rng->pos = ~0U;
		return;
	}

	u64 seed = get_real_time_us();
#ifndef __WINDOWS__
	seed += getpid() + getppid();
#else
	seed += GetCurrentProcessId();
#endif
	pcs_srandom(rng, seed);
}

u64 pcs_rand_range(struct pcs_rng *rng, u64 min, u64 max)
{
	BUG_ON(max < min);

	u64 rnd = pcs_random(rng);
	u64 range = max - min;
	if ((range & (range + 1)) == 0)
		rnd &= range;
	else
		rnd %= range + 1;
	return min + rnd;
}

/*
	This is a 64-bit version of Mersenne Twister pseudorandom number
	generator.

	Copyright (C) 2004, Makoto Matsumoto and Takuji Nishimura,
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions
	are met:

	  1. Redistributions of source code must retain the above copyright
	     notice, this list of conditions and the following disclaimer.

	  2. Redistributions in binary form must reproduce the above copyright
	     notice, this list of conditions and the following disclaimer in the
	     documentation and/or other materials provided with the distribution.

	  3. The names of its contributors may not be used to endorse or promote
	     products derived from this software without specific prior written
	     permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
	A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
	CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
	EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
	PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
	PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
	LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
	NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define NN		312
#define MM		156
#define MATRIX_A	0xB5026F5AA96619E9ULL
#define UM		0xFFFFFFFF80000000ULL	/* Most significant 33 bits */
#define LM		0x7FFFFFFFULL		/* Least significant 31 bits */

u64 pcs_random(struct pcs_rng *rng)
{
	unsigned i;
	u64 x;

	if (unlikely(rng->pos >= NN)) {
		/* generate NN words at one time */
		for (i = 0; i < NN - MM; i++) {
			x = (rng->data[i] & UM) | (rng->data[i + 1] & LM);
			rng->data[i] = rng->data[i + MM] ^ (x >> 1) ^ (x & 1 ? MATRIX_A : 0);
		}
		for (i = NN - MM; i < NN - 1; i++) {
			x = (rng->data[i] & UM) | (rng->data[i + 1] & LM);
			rng->data[i] = rng->data[i + MM - NN] ^ (x >> 1) ^ (x & 1 ? MATRIX_A : 0);
		}
		x = (rng->data[NN - 1] & UM) | (rng->data[0] & LM);
		rng->data[NN - 1] = rng->data[MM - 1] ^ (x >> 1) ^ (x & 1 ? MATRIX_A : 0);
		rng->pos = 0;
	}

	x = rng->data[rng->pos++];
	x ^= (x >> 29) & 0x5555555555555555ULL;
	x ^= (x << 17) & 0x71D67FFFEDA60000ULL;
	x ^= (x << 37) & 0xFFF7EEE000000000ULL;
	x ^= (x >> 43);
	return x;
}

void pcs_srandom(struct pcs_rng *rng, u64 seed)
{
	unsigned i;

	rng->data[0] = seed;
	for (i = 1; i < NN; i++)
		rng->data[i] = 6364136223846793005ULL * (rng->data[i - 1] ^ (rng->data[i - 1] >> 62)) + i;
	rng->pos = NN;
}
