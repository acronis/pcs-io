/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#pragma once

#include "pcs_types.h"

/*
 * Quick selection algorithm with O(n) running time.
 */

/* Rearrange elements of data array of size N so that all items with indexes < k are less than data[k] while
 * all items with indexes > k are greater or equal to data[k]. So this means that on output data[k] is also the
 * k-th element of the data array in the sorted order. The routine uses the caller-provided comparison and swap
 * functions. Both takes element index as the arguments. The comparison function must return an integer less than,
 * equal to, or greater than zero if the first argument is considered to be respectively less than, equal to, or
 * greater than the second. The callbacks may operate on the data array directly or deal with index so the
 * original data will be intact.
 */
void quick_partition(
	void* data, long N, long k,
	int (*compar)(void*, long, long), void (*swap)(void*, long, long)
);

/* Returns k-th element in sorted order from the given (unsorted array) */
unsigned select_uint(unsigned* arr, long N, long k);

/* Returns median element given the unsorted array of values */
static inline unsigned median_uint(unsigned* arr, long N) {
	return select_uint(arr, N, N/2);
}
