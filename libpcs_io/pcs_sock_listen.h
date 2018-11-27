/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_SOCK_LISTEN_H_
#define _PCS_SOCK_LISTEN_H_ 1

#include "pcs_types.h"
#include "pcs_sock.h"
#include "pcs_poll.h"
#include "pcs_process.h"
#include "pcs_net_addr.h"
#include "pcs_net.h"

#define PCS_SOCKLISTEN_THROTTLE_DELAY 100

struct pcs_socklisten
{
	struct pcs_netlisten netlisten;

	void		* private;
	void		(*accepted)(struct pcs_socklisten *, pcs_sock_t fd);

	struct pcs_timer throttle_timer;

	int		sa_len;
	struct sockaddr	sa[0];
};

#define PCS_SK_FREEBIND	1

#define socklisten_from_netlisten(nl) container_of(nl, struct pcs_socklisten, netlisten)
#define socklisten_from_ioconn(conn) container_of(conn, struct pcs_socklisten, netlisten.ioconn)

struct pcs_socklisten * pcs_socklisten_alloc(struct pcs_process * proc, const PCS_NET_ADDR_T * addr);
struct pcs_socklisten * pcs_socklisten_alloc_sa(struct pcs_process * proc, struct sockaddr *sa, int len);
int pcs_socklisten_start(struct pcs_process * proc, struct pcs_socklisten * sh, int flags);
/* Stop accepting connections on @sh, and destroy it. */
void pcs_socklisten_stop(struct pcs_socklisten * sh);

#endif /* _PCS_SOCK_LISTEN_H_ */
