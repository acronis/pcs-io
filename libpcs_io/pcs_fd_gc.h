/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_FD_GC_H_
#define _PCS_FD_GC_H_ 1

#include "std_list.h"

#define PCS_GC_FD_ON_ACCEPT 16

struct pcs_process;

struct pcs_fd_user
{
	struct cd_list	list;
	void		*data;

	int		(*gc)(void *);
};

PCS_API void pcs_init_fd_user(struct pcs_process *, struct pcs_fd_user *, void *, int (*gc)(void *));

int pcs_fd_gc(struct pcs_process *);

/* If err is ENFILE/EMFILE try to collect garbage up to "times" times.
   Return number of collected file descriptors or -err if err is any other error */
int pcs_fd_gc_on_error(struct pcs_process *, int err, int times);

#endif /* _PCS_FD_GC_H_ */
