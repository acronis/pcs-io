/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_random.h"
#include "pcs_sync_io.h"
#include "log.h"
#include "timer.h"

#ifndef __WINDOWS__
#include <unistd.h>
#include <string.h>
#else
#define SystemFunction036 NTAPI SystemFunction036
#include <NTSecAPI.h>
#undef SystemFunction036
#endif

/* We cannot use plain libc random number generator in libpcs_client, we are not allowed to spoil
 * seed probably used by another components.
 */

#ifdef __linux__

unsigned int pcs_random(struct pcs_rng * rdat)
{
	int32_t res;

	if (random_r(&rdat->data, &res))
		BUG();

	return res;
}

void pcs_srandom(struct pcs_rng * rdat, unsigned int seed)
{
	memset(&rdat->data, 0, sizeof(rdat->data));

	if (initstate_r(seed, (char *)rdat->s, sizeof(rdat->s), &rdat->data))
		BUG();
}

#else

unsigned int pcs_random(struct pcs_rng * rdat)
{
	unsigned int res = rdat->data;

	/* PCS_RAND_MAX is expected to be 2^31 - 1 */
	res = (1103515245U * res + 12345) & PCS_RAND_MAX;

	rdat->data = res;
	return res;
}

void pcs_srandom(struct pcs_rng *rdat, unsigned int seed)
{
	rdat->data = seed;
}

#endif

/* Fill buffer with pseudo random content. Returns 0 on success and -1 otherwise */
int pcs_get_urandom(void *buf, int sz)
{
#ifndef __WINDOWS__
	pcs_fd_t fd;
	int ret = pcs_sync_open("/dev/urandom", O_RDONLY, 0, &fd);
	if (ret) {
		pcs_log(LOG_ERR, "Unable open /dev/urandom - %s", strerror(-ret));
		return -1;
	}
	ret = pcs_sync_sread(fd, buf, sz);
	pcs_sync_close(fd);
	if (ret < 0) {
		pcs_log(LOG_ERR, "Can't read from /dev/urandom - %s", strerror(-ret));
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

static unsigned int getseed(void)
{
	unsigned int seed;
	if (pcs_get_urandom(&seed, sizeof(seed))) {
		seed = (unsigned int)get_real_time_us();
#ifndef __WINDOWS__
		seed += getpid() + getppid();
#else
		seed += GetCurrentProcessId();
#endif
	}
	return seed;
}

unsigned int pcs_srandomdev(struct pcs_rng *rdat)
{
	unsigned int seed = getseed();
	pcs_srandom(rdat, seed);
	return seed;
}

unsigned long long pcs_rand_range(struct pcs_rng * rdat, unsigned long long min, unsigned long long max)
{
	BUG_ON(max < min);

	const unsigned long long U64_MAX = ~0ull;
	const unsigned hi = pcs_random(rdat);
	const unsigned lo = pcs_random(rdat);
	const unsigned mid = pcs_random(rdat);

	/* take hi bits [30:10], mid bits [30:10] and lo bits [30:9] */
	const unsigned long long rnd_u64 = ((hi & ~0x3ffull) << 33) | ((mid & ~0x3ffull) << 12) | ((lo & ~0x1fful) >> 9);

	return min + (unsigned long long)((rnd_u64 / (U64_MAX + 1.0)) * (max - min + 1));
}
