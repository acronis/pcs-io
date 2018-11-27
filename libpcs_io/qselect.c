/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "qselect.h"
#include "pcs_types.h"

static inline long median3(void* data, long l, long r, long c, int (*compar)(void*, long, long))
{
	if (compar(data, l, r) < 0) {
		if (compar(data, c, l) < 0) return l;
		if (compar(data, c, r) > 0) return r;
		return c;
	} else {
		if (compar(data, c, l) > 0) return l;
		if (compar(data, c, r) < 0) return r;
		return c;
	}
}

static long find_pivot(void* data, long l, long r, int (*compar)(void*, long, long))
{
	return median3(data, l, r, (l + r) / 2, compar);
}

#define LESS(a, b) compar(data, a, b) < 0
#define SWAP(a, b) do { if (a != b) swap(data, a, b); } while(0)

static long partition(void* data, long l, long r, int (*compar)(void*, long, long), void (*swap)(void*, long, long))
{
	if (r < l + 2) {
		if (r != l && LESS(r, l))
			SWAP(r, l);
		return l;
	}
	long i, p = find_pivot(data, l, r, compar);
	SWAP(p, r); /* Move pivot to the [r] */
	for (i = p = l; i < r; ++i) {
		if (LESS(i, r)) { /* [i] < pivot */
			SWAP(i, p);
			++p;
		}
		/* [l..p-1] < pivot, [p..i] >= pivot */
	}
	SWAP(r, p);
	return p;
}

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
)
{
	long l = 0, r = N - 1;
	for (;;) {
		long p = partition(data, l, r, compar, swap);
		if (p == k) return;
		if (p < k)
			l = p + 1;
		else
			r = p - 1;
	}
}

static int compar_uint(void* data, long i, long j)
{
	unsigned* arr = data;
	if (arr[i] < arr[j])
		return -1;
	if (arr[i] > arr[j])
		return 1;
	return 0;
}

static void swap_uint(void* data, long i, long j)
{
	unsigned* arr = data;
	unsigned tmp = arr[i];
	arr[i] = arr[j];
	arr[j] = tmp;
}

/* Returns k-th element in sorted order from the given (unsorted array) */
unsigned select_uint(unsigned* arr, long N, long k)
{
	quick_partition(arr, N, k, compar_uint, swap_uint);
	return arr[k];
}

