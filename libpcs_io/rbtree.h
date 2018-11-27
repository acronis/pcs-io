/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

/*
 * RB tree in C, easy to use implementation.
 * Author: Kirill Korotaev <dev@parallels.com>
 */

/*
 * Main primitives:
 *   rb_search_node - find node with given key
 *   rb_delete      - remove rb_node from the tree
 *   rb_insert      - insert rb_node to the tree (no duplicates allowed!)
 *   rb_first/rb_last - returns min/max nodes
 *   rb_for_each    - loop over all elements in the tree in sorted order
 * NOTE: Caller must protect tree operations with appropriate locks
 */

#ifndef	__PRL_RBTREE_H__
#define	__PRL_RBTREE_H__

#include <stddef.h>
#include "pcs_types.h"

#define	RBTREE_RED		0
#define	RBTREE_BLACK	1

struct rb_node
{
	ULONG_PTR rb_parent;		/* the lowest bit is used for color */
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};

struct rb_root
{
	struct rb_node *rb_node;
};

static inline void *__rb_entry_safe(const struct rb_node *node, int offs)
{
	/* safe version of rb_entry makes sure compiler doesn't optimize out check for &ptr->member==NULL
	 * gcc 4.3+ and clang believe that such address is never NULL.
	 * Interesting... do they optimize it out if member is the very first member? */
	return node ? (char *)node - offs : NULL;
}

#define rb_entry(ptr, type, member)		container_of(ptr, type, member)
#define rb_entry_safe(ptr, type, member)	((type *)__rb_entry_safe(ptr, offsetof(type, member)))

#define rb_empty(root)	((root)->rb_node == NULL)

/* rb_parent field is used for parent:31 + color:1 store */
#define rb_parent(n)	((struct rb_node *)((n)->rb_parent & ~1))

static inline void rb_init(struct rb_root *root)
{
	root->rb_node = NULL;
}

PCS_API void rb_insert_fixup(struct rb_root *, struct rb_node *);
PCS_API void rb_insert_fixup_augmented(struct rb_root *, struct rb_node *, void (*propagate)(struct rb_node *));
PCS_API void rb_delete(struct rb_root *, struct rb_node *);
PCS_API void rb_delete_augmented(struct rb_root *, struct rb_node *, void (*propagate)(struct rb_node *));

PCS_API struct rb_node *rb_next(struct rb_node *);
PCS_API struct rb_node *rb_prev(struct rb_node *);
PCS_API struct rb_node *rb_first(struct rb_root *);
PCS_API struct rb_node *rb_last(struct rb_root *);

/* comparator function for node element: should return {<0, 0, >0} if
 * key { <node->key, ==node->key, >node->key }
 * the tree will be ordered in increasing order
 */
typedef int (*rb_cmp_fn_t)(struct rb_node *node, ULONG_PTR key);

static inline struct rb_node *rb_search_node(struct rb_root *root, rb_cmp_fn_t cmp_fn, ULONG_PTR key)
{
	int cmp_res;
	struct rb_node *node = root->rb_node;

	while (node) {
		cmp_res = cmp_fn(node, key);
		if (cmp_res < 0)
			node = node->rb_left;
		else if (cmp_res > 0)
			node = node->rb_right;
		else
			return node;
	}
	return NULL;
}

/* Lookup nearest key */
static inline int rb_lookup_(struct rb_node **pnode, rb_cmp_fn_t cmp_fn, ULONG_PTR key)
{
	int cmp_res = 0;

	while (*pnode) {
		cmp_res = cmp_fn(*pnode, key);
		if (cmp_res < 0) {
			if ((*pnode)->rb_left)
				*pnode = (*pnode)->rb_left;
			else
				break;
		} else if (cmp_res > 0) {
			if ((*pnode)->rb_right)
				*pnode = (*pnode)->rb_right;
			else
				break;
		} else
			break;
	}
	return cmp_res;
}

/* Find first node exceeding key */
static inline struct rb_node *rb_find_next(struct rb_root *root, rb_cmp_fn_t cmp_fn, ULONG_PTR key)
{
	struct rb_node *node = root->rb_node;
	int cmp_res = rb_lookup_(&node, cmp_fn, key);

	while (node && cmp_res >= 0)
		if ((node = rb_next(node)))
			cmp_res = cmp_fn(node, key);

	return node;
}

/* Find first node less than the key */
static inline struct rb_node *rb_find_prev(struct rb_root *root, rb_cmp_fn_t cmp_fn, ULONG_PTR key)
{
	struct rb_node *node = root->rb_node;
	int cmp_res = rb_lookup_(&node, cmp_fn, key);

	while (node && cmp_res <= 0)
		if ((node = rb_prev(node)))
			cmp_res = cmp_fn(node, key);

	return node;
}

/* Find first node equal or exceeding key */
static inline struct rb_node *rb_find_next_or_eq(struct rb_root *root, rb_cmp_fn_t cmp_fn, ULONG_PTR key)
{
	struct rb_node *node = root->rb_node;
	int cmp_res = rb_lookup_(&node, cmp_fn, key);

	while (node && cmp_res > 0)
		if ((node = rb_next(node)))
			cmp_res = cmp_fn(node, key);

	return node;
}

/* Find first node equal or less than the key */
static inline struct rb_node *rb_find_prev_or_eq(struct rb_root *root, rb_cmp_fn_t cmp_fn, ULONG_PTR key)
{
	struct rb_node *node = root->rb_node;
	int cmp_res = rb_lookup_(&node, cmp_fn, key);

	while (node && cmp_res < 0)
		if ((node = rb_prev(node)))
			cmp_res = cmp_fn(node, key);

	return node;
}

static inline void rb_tree_insert(struct rb_node *parent,
		struct rb_node **parent_link, struct rb_node *new_node)
{
	/* insert new node below the parent, where parent_link is either
	 * &parent->rb_right or &parent->rb_left */
	new_node->rb_parent = (ULONG_PTR)parent;	/* RED initially */
	new_node->rb_left = new_node->rb_right = NULL;
	*parent_link = new_node;
}

/* insert a node into the tree. if such node already exists it still inserts and returns existing node as well - can be used for BUG_ONs */
static inline struct rb_node *rb_insert_node(struct rb_root *root,
					struct rb_node *new_node,
					rb_cmp_fn_t cmp_fn, ULONG_PTR key)
{
	int cmp_res;
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct rb_node *res = NULL;

	while (*node) {
		parent = *node;
		cmp_res = cmp_fn(*node, key);
		if (cmp_res < 0)
			node = &(*node)->rb_left;
		else if (cmp_res == 0) {
			res = *node;
			node = &(*node)->rb_left;
		} else
			node = &(*node)->rb_right;
	}

	/* insert & rebalance rb-tree */
	rb_tree_insert(parent, node, new_node);
	rb_insert_fixup(root, new_node);

	return res;
}

/* Destructive iteration in sorted order. */
static inline void rb_destroy(struct rb_root *root, void (*free_node_cb)(struct rb_node *))
{
	struct rb_node *node = rb_first(root), *right;
	struct rb_node *parent;

	while (node) {
		right = node->rb_right;
		parent = rb_parent(node);

		free_node_cb(node);

		if (right) {
			node = right;
			right->rb_parent = (ULONG_PTR)parent;
			/* go left as far as we can */
			while (node->rb_left)
				node = node->rb_left;
		} else {
			while (parent && node == parent->rb_right) {
				node = parent;
				parent = rb_parent(node);
			}
			node = parent;
		}
	}
}

static inline void rb_destroy2(struct rb_root *root, void (*free_node_cb)(struct rb_node *, void*), void* priv)
{
	struct rb_node *node = rb_first(root), *right;
	struct rb_node *parent;

	while (node) {
		right = node->rb_right;
		parent = rb_parent(node);

		free_node_cb(node, priv);

		if (right) {
			node = right;
			right->rb_parent = (ULONG_PTR)parent;
			/* go left as far as we can */
			while (node->rb_left)
				node = node->rb_left;
		} else {
			while (parent && node == parent->rb_right) {
				node = parent;
				parent = rb_parent(node);
			}
			node = parent;
		}
	}
}

/* Destructive iteration in reverse-sorted order. */
static inline void rb_destroy_reverse(struct rb_root *root, void (*free_node_cb)(struct rb_node *))
{
	struct rb_node *node = rb_last(root), *left;
	struct rb_node *parent;

	while (node) {
		left = node->rb_left;
		parent = rb_parent(node);

		free_node_cb(node);

		if (left) {
			node = left;
			left->rb_parent = (ULONG_PTR)parent;
			/* go right as far as we can */
			while (node->rb_right)
				node = node->rb_right;
		} else {
			while (parent && node == parent->rb_left) {
				node = parent;
				parent = rb_parent(node);
			}
			node = parent;
		}
	}
}

static inline void rb_destroy_reverse2(struct rb_root *root, void (*free_node_cb)(struct rb_node *, void*), void* priv)
{
	struct rb_node *node = rb_last(root), *left;
	struct rb_node *parent;

	while (node) {
		left = node->rb_left;
		parent = rb_parent(node);

		free_node_cb(node, priv);

		if (left) {
			node = left;
			left->rb_parent = (ULONG_PTR)parent;
			/* go right as far as we can */
			while (node->rb_right)
				node = node->rb_right;
		} else {
			while (parent && node == parent->rb_left) {
				node = parent;
				parent = rb_parent(node);
			}
			node = parent;
		}
	}
}

/* Exchange content of 2 rb-trees */
static inline void rb_swap(struct rb_root *a, struct rb_root *b)
{
	struct rb_node *tmp = a->rb_node;
	a->rb_node = b->rb_node;
	b->rb_node = tmp;
}

#define rb_for_each_(typeof_pos, pos, member, first, next)	\
	for (pos = rb_entry_safe(first, typeof_pos, member);	\
			pos != NULL;				\
			pos = rb_entry_safe(next(&pos->member), typeof_pos, member))

#define rb_for_each(typeof_pos, pos, root, member)		\
	rb_for_each_(typeof_pos, pos, member, rb_first(root), rb_next)

#define rb_for_each_reverse(typeof_pos, pos, root, member)	\
	rb_for_each_(typeof_pos, pos, member, rb_last(root), rb_prev)

#endif
