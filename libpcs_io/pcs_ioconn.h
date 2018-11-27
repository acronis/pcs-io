/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_IOCONN_H_
#define _PCS_IOCONN_H_ 1

#include "pcs_types.h"
#include "pcs_sock.h"
#include "std_list.h"

#ifndef __WINDOWS__

struct pcs_ioconn
{
	struct cd_list	list;

	int		fd;
	char		dead;
	int		actual_mask;	/* Actual mask loaded to kernel epoll */
	int		next_mask;	/* Mask planned for loading to epoll */

	struct pcs_process * proc;

	void(*data_ready)(struct pcs_ioconn *);
	void(*write_space)(struct pcs_ioconn *);
	void(*error_report)(struct pcs_ioconn *);
	void(*destruct)(struct pcs_ioconn *);
};

void pcs_ioconn_init(struct pcs_process *, struct pcs_ioconn * conn);
void pcs_ioconn_close(struct pcs_ioconn * conn);
void pcs_ioconn_destruct(struct pcs_ioconn * conn);

void pcs_ioconn_register(struct pcs_ioconn * conn);
void pcs_ioconn_unregister(struct pcs_ioconn * conn);
void pcs_ioconn_schedule(struct pcs_ioconn * conn);

/* internal API for eventloop */
void ioconn_kill_all(void * arg);

static inline void pcs_ioconn_reset(struct pcs_ioconn * conn)
{
	conn->fd = -1;
}

#else /* __WINDOWS__ */

#define ioconn_kill_all		NULL

#endif /* __WINDOWS__ */

#endif /* _PCS_IOCONN_H_ */
