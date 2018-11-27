/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _RANDOM_H_
#define _RANDOM_H_ 1

#include "pcs_types.h"
#include <stdlib.h>

/* Maximum value that can be returned by the pcs_random function (2^31 - 1) */
#define PCS_RAND_MAX 0x7FFFFFFFU

struct pcs_rng
{
#ifdef __linux__
	struct random_data data;
	unsigned long long s[4];
#else
	int data;
#endif
};

/* Fill buffer with pseudo random content. Returns 0 on success and -1 otherwise */
PCS_API int pcs_get_urandom(void *buf, int sz);
/* Returns value in range [0; PCS_RAND_MAX] */
PCS_API unsigned int pcs_random(struct pcs_rng *);
PCS_API unsigned long long pcs_rand_range(struct pcs_rng *, unsigned long long min, unsigned long long max);
PCS_API void pcs_srandom(struct pcs_rng *, unsigned int seed);
PCS_API unsigned int pcs_srandomdev(struct pcs_rng *);

#endif /* _RANDOM_H_ */
