/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_RDMA_LISTEN_H_
#define _PCS_RDMA_LISTEN_H_ 1

#include <rdma/rdma_cma.h>

#include "pcs_types.h"
#include "pcs_sock.h"
#include "pcs_process.h"
#include "pcs_net_addr.h"
#include "pcs_net.h"

struct pcs_rdmalisten
{
	struct pcs_netlisten netlisten;

	struct rdma_cm_id         *listen_cmid;

	int		sa_len;
	struct sockaddr	sa[0];
};

#define rdmalisten_from_netlisten(nl) container_of(nl, struct pcs_rdmalisten, netlisten)
#define rdmalisten_from_ioconn(conn) container_of(conn, struct pcs_rdmalisten, netlisten.ioconn)

struct pcs_rdmalisten * pcs_rdmalisten_alloc(struct pcs_process * proc, const PCS_NET_ADDR_T * addr);

#endif /* _PCS_RDMA_LISTEN_H_ */
