/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "std_list.h"

static void cd_list_merge(struct cd_list *list1, struct cd_list *list2, int (*cmp_fn)(struct cd_list *, struct cd_list *))
{
	struct cd_list *i1 = list1->next, *i2 = list2->next;

	while (i1 != list1 && i2 != list2) {
		if (cmp_fn(i1, i2) < 0) {
			struct cd_list *tmp = i1;
			i1 = i1->next;
			cd_list_move_tail(tmp, i2);
		} else {
			i2 = i2->next;
		}
	}

	cd_list_splice(list2, list1);
}

void cd_list_sort(struct cd_list *head, int (*cmp_fn)(struct cd_list *, struct cd_list *))
{
	struct cd_list binlist[64];
	unsigned maxbin = 0, bin;

	while (!cd_list_empty(head)) {
		CD_LIST_HEAD(tmp);
		cd_list_move_tail(head->next, &tmp);

		for (bin = 0; bin < maxbin && !cd_list_empty(&binlist[bin]); bin++)
			cd_list_merge(&tmp, &binlist[bin], cmp_fn);

		if (bin == maxbin)
			maxbin++;

		cd_list_init(&binlist[bin]);
		cd_list_splice_tail(&tmp, &binlist[bin]);
	}

	for (bin = 0; bin < maxbin; bin++)
		cd_list_merge(head, &binlist[bin], cmp_fn);
}
