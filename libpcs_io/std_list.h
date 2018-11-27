/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __STD_LIST_H__
#define __STD_LIST_H__

#include <stddef.h>
#include "pcs_types.h"

struct cd_list
{
	struct cd_list *next, *prev;
};

#define CD_LIST_INIT(name) { &(name), &(name) }
#define CD_LIST_HEAD(name) \
	    struct cd_list name = CD_LIST_INIT(name)

#define cd_list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define cd_list_first_entry(ptr, type, member) \
	cd_list_entry((ptr)->next, type, member)

#define cd_list_last_entry(ptr, type, member) \
	cd_list_entry((ptr)->prev, type, member)

static __inline void cd_list_init(struct cd_list *ptr)
{
	ptr->next = ptr;
	ptr->prev = ptr;
}

static __inline void __cd_list_add(struct cd_list *newl, struct cd_list *prev, struct cd_list *next)
{
	next->prev = newl;
	newl->next = next;
	newl->prev = prev;
	prev->next = newl;
}

/* add element to list head */
static __inline void cd_list_add(struct cd_list *newl, struct cd_list *head)
{
	__cd_list_add(newl, head, head->next);
}

/* add element to list tail */
static __inline void cd_list_add_tail(struct cd_list *newl, struct cd_list *head)
{
	__cd_list_add(newl, head->prev, head);
}

#define CD_LIST_POISON_NEXT  ((void *)0x00112233)
#define CD_LIST_POISON_PREV  ((void *)0x00445566)

static __inline void __cd_list_del(struct cd_list *prev, struct cd_list *next)
{
	next->prev = prev;
	prev->next = next;
}

static __inline void cd_list_del(struct cd_list *elem)
{
	__cd_list_del(elem->prev, elem->next);

	elem->next = (struct cd_list *)CD_LIST_POISON_NEXT;
	elem->prev = (struct cd_list *)CD_LIST_POISON_PREV;
}

static __inline void cd_list_del_init(struct cd_list *elem)
{
	__cd_list_del(elem->prev, elem->next);
	cd_list_init(elem);
}

static __inline int cd_list_empty(const struct cd_list* head)
{
	return (head->next == head);
}

static __inline void cd_list_move(struct cd_list *elem, struct cd_list *head)
{
	__cd_list_del(elem->prev, elem->next);
	cd_list_add(elem, head);
}

static __inline void cd_list_move_tail(struct cd_list *elem, struct cd_list *head)
{
	__cd_list_del(elem->prev, elem->next);
	cd_list_add_tail(elem, head);
}

static __inline void cd_list_splice(struct cd_list *list, struct cd_list *head)
{
	if (!cd_list_empty(list)) {
		struct cd_list *first = list->next;
		struct cd_list *last = list->prev;
		struct cd_list *at = head->next;

		first->prev = head;
		head->next = first;

		last->next = at;
		at->prev = last;

		cd_list_init(list);
	}
}

static __inline void cd_list_splice_tail(struct cd_list *list, struct cd_list *head)
{
	if (!cd_list_empty(list)) {
		struct cd_list *first = list->next;
		struct cd_list *last = list->prev;
		struct cd_list *at = head->prev;

		first->prev = at;
		at->next = first;

		last->next = head;
		head->prev = last;

		cd_list_init(list);
	}
}

#define cd_list_for_each_entry(typeof_pos, pos, head, member) \
	for (pos = cd_list_entry((head)->next, typeof_pos, member); \
			&pos->member != (head); \
			pos = cd_list_entry(pos->member.next, typeof_pos, member))

#define cd_list_for_each_entry_reverse(typeof_pos, pos, head, member) \
	for (pos = cd_list_entry((head)->prev, typeof_pos, member); \
			&pos->member != (head); \
			pos = cd_list_entry(pos->member.prev, typeof_pos, member))

#define cd_list_for_each_entry_safe(typeof_pos, pos, n, head, member) \
	for (pos = cd_list_entry((head)->next, typeof_pos, member), \
			n = cd_list_entry(pos->member.next, typeof_pos, member); \
			&pos->member != (head); \
			pos = n, n = cd_list_entry(n->member.next, typeof_pos, member))

#define cd_list_for_each_entry_reverse_safe(typeof_pos, pos, p, head, member) \
	for (pos = cd_list_entry((head)->prev, typeof_pos, member),	\
			p = cd_list_entry(pos->member.prev, typeof_pos, member); \
			&pos->member != (head); \
			pos = p, p = cd_list_entry(pos->member.prev, typeof_pos, member))

/*
 * Continue to iterate over list of given type, continuing after the current
 * position.
 */
#define cd_list_for_each_entry_continue(typeof_pos, pos, head, member) \
	for (pos = cd_list_entry(pos->member.next, typeof_pos, member); \
			&pos->member != (head); \
			pos = cd_list_entry(pos->member.next, typeof_pos, member))

/*
 * Continue to iterate over list of given type backwards, continuing after the
 * current position.
 */
#define cd_list_for_each_entry_continue_reverse(typeof_pos, pos, head, member) \
	for (pos = cd_list_entry(pos->member.prev, typeof_pos, member); \
			&pos->member != (head); \
			pos = cd_list_entry(pos->member.prev, typeof_pos, member))

PCS_API void cd_list_sort(struct cd_list *head, int (*cmp_fn)(struct cd_list *, struct cd_list *));


struct cd_hlist_head {
	struct cd_hlist_node *first;
};

struct cd_hlist_node {
	struct cd_hlist_node *next, **pprev;
};

static inline void cd_hlist_head_init(struct cd_hlist_head * head)
{
	head->first = NULL;
}

static inline void cd_hlist_node_init(struct cd_hlist_node * node)
{
	node->next = NULL;
	node->pprev = NULL;
}

static inline int cd_hlist_empty(const struct cd_hlist_head *h)
{
	return !h->first;
}

#define cd_hlist_entry(ptr, type, member) container_of(ptr,type,member)

static inline void __cd_hlist_del(struct cd_hlist_node *n)
{
	struct cd_hlist_node *next = n->next;
	struct cd_hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

static inline void cd_hlist_del(struct cd_hlist_node *n)
{
	__cd_hlist_del(n);
	n->next = (struct cd_hlist_node *)CD_LIST_POISON_NEXT;
	n->pprev = (struct cd_hlist_node **)CD_LIST_POISON_PREV;
}

#define cd_hlist_for_each_entry(typeof_pos, tpos, pos, head, member)				\
	for (pos = (head)->first, tpos = cd_hlist_entry(pos, typeof_pos, member);	\
	     pos;									\
	     pos = pos->next, tpos = cd_hlist_entry(pos, typeof_pos, member))

#define cd_hlist_for_each_entry_safe(typeof_pos, tpos, pos, n, head, member)			\
	for (pos = (head)->first, n = ((pos) ? (pos)->next : NULL), tpos = cd_hlist_entry(pos, typeof_pos, member); \
	     pos;									\
	     pos = n, n = ((pos) ? (pos)->next : NULL), tpos = cd_hlist_entry(pos, typeof_pos, member))

static inline void cd_hlist_add_head(struct cd_hlist_node *n, struct cd_hlist_head *h)
{
	struct cd_hlist_node *first = h->first;
	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

static inline int cd_hlist_unhashed(const struct cd_hlist_node *h)
{
	return !h->pprev;
}


#endif /* __STD_LIST_H__ */
