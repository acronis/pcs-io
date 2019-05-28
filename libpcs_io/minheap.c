/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "minheap.h"

static struct mh_node* mh_next_sibling(struct mh_node *n)
{
	return cd_list_first_entry(&n->siblings, struct mh_node, siblings);
}

static struct mh_node* mh_prev_sibling(struct mh_node *n)
{
	return cd_list_last_entry(&n->siblings, struct mh_node, siblings);
}

/* retrieve a pointer to a field in mh_node or mh_root that points to @n */
static struct mh_node** mh_link(struct mh_root *h, struct mh_node *n)
{
	struct mh_node *p = n->parent;
	if (unlikely(p == NULL))
		return &h->root;

	if (n == p->left)
		return &p->left;
	else if (n == p->right)
		return &p->right;
	else
		BUG();
}

static void mh_set_child(struct mh_node *p, struct mh_node **link, struct mh_node *c)
{
	*link = c;
	if (c != NULL)
		c->parent = p;
}

/* Swap entries @x and @y of a minheap @h. If these two nodes are a child and a parent,
   then @x must point to the parent. */
static void mh_swap(struct mh_root *h, struct mh_node * __restrict x, struct mh_node * __restrict y)
{
	struct mh_node *px = x->parent, *py = y->parent;
	struct mh_node **xlink = mh_link(h, x), **ylink = mh_link(h, y);
	struct mh_node *xl = x->left, *xr = x->right;
	struct mh_node *yl = y->left, *yr = y->right;

	if (x->left == y) {
		mh_set_child(x, &x->left, yl);
		mh_set_child(x, &x->right, yr);
		mh_set_child(y, &y->left, x);
		mh_set_child(y, &y->right, xr);

		x->parent = y;
		y->parent = px;

		*xlink = y;
	} else if (x->right == y) {
		mh_set_child(x, &x->left, yl);
		mh_set_child(x, &x->right, yr);
		mh_set_child(y, &y->left, xl);
		mh_set_child(y, &y->right, x);

		x->parent = y;
		y->parent = px;

		*xlink = y;
	} else if (px == py) {
		struct mh_node *t = px->left;
		px->left = px->right;
		px->right = t;
	} else {
		mh_set_child(x, &x->left, yl);
		mh_set_child(x, &x->right, yr);
		mh_set_child(y, &y->left, xl);
		mh_set_child(y, &y->right, xr);

		x->parent = py;
		y->parent = px;

		*xlink = y;
		*ylink = x;
	}

	struct cd_list t;
	cd_list_add(&t, &x->siblings);
	cd_list_move_tail(&x->siblings, &y->siblings);
	cd_list_move_tail(&y->siblings, &t);
	cd_list_del(&t);

	if (unlikely(h->bottom_right == x))
		h->bottom_right = y;
	else if (unlikely(h->bottom_right == y))
		h->bottom_right = x;
}

static void mh_swim_up(struct mh_root *h, struct mh_node *n)
{
	while (n->parent != NULL && h->cmp(n, n->parent) < 0)
		mh_swap(h, n->parent, n);
}

static void mh_swim_down(struct mh_root *h, struct mh_node *n)
{
	int sl, sr;
	do {
		sl = n->left != NULL && h->cmp(n, n->left) > 0;
		sr = n->right != NULL && h->cmp(n, n->right) > 0;

		if (sl && sr) {
			if (h->cmp(n->left, n->right) < 0)
				mh_swap(h, n, n->left);
			else
				mh_swap(h, n, n->right);
		} else if (sl) {
			mh_swap(h, n, n->left);
		} else if (sr) {
			mh_swap(h, n, n->right);
		}
	} while (sl || sr);
}

static void mh_insert_as_bottom_right(struct mh_root *h, struct mh_node *n)
{
	struct mh_node *b = h->bottom_right;
	struct mh_node *p;
	struct mh_node **link;

	const int full = (h->count & (h->count + 1)) == 0;
	if (likely(!full)) {
		p = b->parent;

		if (b == p->left) {
			BUG_ON(p->right != NULL);
			link = &p->right;
		} else {
			p = mh_next_sibling(p);
			BUG_ON(p->left != NULL);
			link = &p->left;
		}

		cd_list_add(&n->siblings, &b->siblings);
	} else if (b != NULL) {
		p = mh_next_sibling(b);

		BUG_ON(p->left != NULL);
		link = &p->left;

		cd_list_init(&n->siblings);
	} else {
		BUG_ON(!mh_empty(h));

		p = NULL;
		link = &h->root;
		cd_list_init(&n->siblings);
	}

	n->parent = p;
	n->left = n->right = NULL;

	*link = n;
	++h->count;
	h->bottom_right = n;
}

static void mh_delete_bottom_right(struct mh_root *h)
{
	struct mh_node *b = h->bottom_right;
	struct mh_node *p = b->parent;

	BUG_ON(h->count > 1 && p == NULL);
	BUG_ON(b->left != NULL || b->right != NULL);

	--h->count;

	if (unlikely(h->count == 0)) {
		b->parent = NULL;
		h->root = NULL;
		h->bottom_right = NULL;
		return;
	}

	const int full = (h->count & (h->count + 1)) == 0;
	if (likely(!full)) {
		if (p->left == b) {
			BUG_ON(p->right != NULL);
			p->left = NULL;
		} else {
			BUG_ON(p->right != b);
			p->right = NULL;
		}

		h->bottom_right = mh_prev_sibling(b);
	} else {
		BUG_ON(!cd_list_empty(&b->siblings));
		BUG_ON(p->left != b || p->right != NULL);

		p->left = NULL;

		h->bottom_right = mh_prev_sibling(p);
	}

	cd_list_del(&b->siblings);
	b->parent = NULL;
}

void mh_reweigh_node(struct mh_root *h, struct mh_node *n)
{
	mh_swim_up(h, n);
	mh_swim_down(h, n);
}

void mh_insert(struct mh_root *h, struct mh_node *n)
{
	mh_insert_as_bottom_right(h, n);
	mh_swim_up(h, n);
}

void mh_delete(struct mh_root *h, struct mh_node *n)
{
	BUG_ON(mh_empty(h));

	struct mh_node *b = h->bottom_right;
	if (likely(n != b)) {
		mh_swap(h, n, b);
		mh_delete_bottom_right(h);
		mh_reweigh_node(h, b);
	} else {
		mh_delete_bottom_right(h);
	}
}
