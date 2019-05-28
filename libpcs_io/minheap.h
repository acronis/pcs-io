/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#pragma once

/*
  This file implement a min-heap.

  A quick recap (see https://algs4.cs.princeton.edu/24pq/ for more detail):

  Min-heap is a perfectly balanced binary tree of items that have weights (or priorities)
  associated to them. This tree satisfies the "min-heap property": the weight of a node
  is less than or equal to weights of the children of it. Perfect balancing means that
  all leaf nodes are located at the same depth.

  Min-heap supports the following operations with complexity logarithmic in the size of a heap:
  * insert an item,
  * remove an item of the minimal weight,
  * associate a new weight to an item.

  A classical implementation of a min-heap uses an array of pointers to items of a heap,
  where indices of children of an item k are 2*k+1 and 2*k+2.

  This implementation does not allocate additional memory. Instead, it requires users
  to embed struct mh_node into items that are added to a heap. It also allows to remove
  any item, not just the minimal-weight one (also in logarithmic time).
*/

#include <pcs_types.h>
#include <std_list.h>
#include <bug.h>

struct mh_node
{
	struct cd_list	siblings;	/* each level of a heap is organised as a circular list */
	struct mh_node	*parent;
	struct mh_node	*left, *right;
};

struct mh_root
{
	struct mh_node	*root;

	/* private to minheap */
	u32		count;
	struct mh_node	*bottom_right;

	int (*cmp)(struct mh_node *x, struct mh_node *y);
};


#define mh_entry(ptr, type, member) container_of(ptr, type, member)

static inline void mh_init(struct mh_root *h, int (*cmp)(struct mh_node *x, struct mh_node *y))
{
	h->root = NULL;
	h->count = 0;
	h->bottom_right = NULL;
	h->cmp = cmp;
}

static inline int mh_empty(const struct mh_root *h)
{
	return h->count == 0;
}

PCS_API void mh_insert(struct mh_root *h, struct mh_node *n);
PCS_API void mh_delete(struct mh_root *h, struct mh_node *n);
/* Correct the location of a node @n in a minheap @h after the weight of it is changed. */
PCS_API void mh_reweigh_node(struct mh_root *h, struct mh_node *n);
