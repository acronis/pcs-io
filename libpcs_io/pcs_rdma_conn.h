/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_RDMA_CONN_H_
#define _PCS_RDMA_CONN_H_ 1

#include <rdma/rdma_cma.h>

#include "pcs_types.h"
#include "pcs_sock.h"
#include "pcs_process.h"
#include "pcs_net_addr.h"
#include "pcs_net.h"

struct pcs_rdmaconnect
{
	struct pcs_netconnect netconn;

	struct rdma_cm_id	*cmid;
	struct pcs_rdmaio       *rio;
	int		sa_len;
	struct sockaddr	sa[0];
};

#define rdmaconn_from_netconn(conn) container_of(conn, struct pcs_rdmaconnect, netconn)
#define rdmaconn_from_ioconn(conn) container_of(conn, struct pcs_rdmaconnect, netconn.ioconn)

struct pcs_rdmaconnect * pcs_rdmaconnect_init(struct pcs_process * proc, PCS_NET_ADDR_T *addr);

#endif /* _PCS_RDMA_CONN_H_ */
