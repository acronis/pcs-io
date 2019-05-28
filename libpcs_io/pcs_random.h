/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _RANDOM_H_
#define _RANDOM_H_ 1

#include "pcs_types.h"

struct pcs_rng
{
	u64 data[312];
	unsigned pos;
};

/* Fill buffer with pseudo random content. Returns 0 on success and -1 otherwise */
PCS_API int pcs_get_urandom(void *buf, int sz);
PCS_API u64 pcs_random(struct pcs_rng *rng);
PCS_API u64 pcs_rand_range(struct pcs_rng *rng, u64 min, u64 max);
PCS_API void pcs_srandom(struct pcs_rng *rng, u64 seed);
PCS_API void pcs_srandomdev(struct pcs_rng *rng);

#endif /* _RANDOM_H_ */
