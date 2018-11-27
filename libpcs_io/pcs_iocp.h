/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_IOCP_H_
#define _PCS_IOCP_H_ 1

#include "pcs_types.h"

#ifdef __WINDOWS__

struct pcs_iocp
{
	OVERLAPPED	overlapped;
	void		(*done)(struct pcs_iocp *iocp);
};

struct pcs_process;

void pcs_iocp_attach(struct pcs_process *proc, HANDLE handle, void *key);
void pcs_iocp_cancel(HANDLE handle, struct pcs_iocp *iocp);
void pcs_iocp_send(struct pcs_process *proc, struct pcs_iocp *iocp);
int pcs_iocp_result(struct pcs_iocp *iocp);

#endif /* __WINDOWS__ */

#endif /* _PCS_IOCP_H_ */
