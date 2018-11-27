/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_SOCK_CONN_H_
#define _PCS_SOCK_CONN_H_ 1

#include "pcs_types.h"
#include "pcs_sock.h"
#include "pcs_process.h"
#include "pcs_net_addr.h"
#include "pcs_net.h"

struct pcs_sockconnect
{
	struct pcs_netconnect netconn;
	int		error;
	void		*private;
	void		(*complete)(struct pcs_sockconnect *);

	int		sa_len;
	struct sockaddr	sa[0];
};

#define sockconn_from_netconn(conn) container_of(conn, struct pcs_sockconnect, netconn)
#define sockconn_from_ioconn(conn) container_of(conn, struct pcs_sockconnect, netconn.ioconn)

struct pcs_sockconnect * pcs_sockconnect_init(struct pcs_process * proc, PCS_NET_ADDR_T *addr);
struct pcs_sockconnect * pcs_sockconnect_init_sa(struct pcs_process * proc, struct sockaddr *sa, int len);
void pcs_sockconnect_start(struct pcs_process * proc, struct pcs_sockconnect * sh);
void pcs_sockconnect_abort(struct pcs_sockconnect * conn, int error);

#endif /* _PCS_SOCK_CONN_H_ */

