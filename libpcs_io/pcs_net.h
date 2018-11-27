/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_NET_H_
#define _PCS_NET_H_ 1

#include "pcs_types.h"
#include "pcs_ioconn.h"

struct pcs_msg;
struct pcs_netio;
struct pcs_netconnect;
struct pcs_netlisten;

/*** netio -- represents network connection in ready-to-use "connected" state ***/

struct pcs_netio_tops {
	/* call pcs_ioconn_register() for proper ioconn-s */
	void  (*register_io)(struct pcs_netio *netio);

	/* suspend polling events on netio->ioconn.fd */
	void  (*throttle)(struct pcs_netio *netio);

	/* resume polling events on netio->ioconn.fd */
	void  (*unthrottle)(struct pcs_netio *netio);

	/* queue message for sending */
	void  (*send_msg)(struct pcs_netio *netio, struct pcs_msg *msg);

	/* try to cancel message send */
	int   (*cancel_msg)(struct pcs_msg *msg);

	/* tear down connection, finilize all in-flight messages with error */
	void  (*abort_io)(struct pcs_netio *netio, int error);

	/* makes sense only for sockio, setsockopt() SO_SNDBUF and SO_RCVBUF:
	 * use <tcp_sndbuf, tcp_rcvbuf> if PCS_SOCK_F_CORK, <local_sndbuf, 0> otherwise
	 */
	void  (*setup_buffers)(struct pcs_netio *netio, int tcp_sndbuf, int tcp_rcvbuf, int local_sndbuf);

	/* TRACE() low-level info about problematic connection */
	void  (*trace_health)(struct pcs_netio *netio, const char *role, unsigned long long id_val);

	/* inquire current address to which the local endpoint of connection is bound */
	int   (*getmyname)(struct pcs_netio *netio, PCS_NET_ADDR_T * addr);

	/* inquire current address to which the remote endpoint of connection is bound */
	int   (*getpeername)(struct pcs_netio *netio, PCS_NET_ADDR_T * addr);

	/* number of packet retransmits happened since last inquiry */
	unsigned int (*get_retrans_stat)(struct pcs_netio *netio);
};

struct pcs_netio {
	struct pcs_ioconn ioconn;
	void *parent;

	/* transport methods */
	struct pcs_netio_tops *tops;

	/* callbacks */

	/* create pcs_msg by inline_buffer pointing to the head of new incoming message */
	struct pcs_msg *(*getmsg)(struct pcs_netio *netio, char *inline_buffer);

	/* report "connection closed" event: graceful shutdown or abort_io. Notice, that */
	/* the handler could be called twice: once on graceful shutdown and from abort_io()
	 */
	void  (*eof)(struct pcs_netio *netio);
};

/*** netconn -- represents network connection initiator in "connecting" state ***/

struct pcs_netconnect_tops {
	/* switch nc to erroneous state, call handle_errors callback to show the error
	 * to user and give her a chance to reconnect, then call nc_complete callback
	 */
	void (*abort_connect)(struct pcs_netconnect * nc, int error);


	/* inquire current address to which the local endpoint of connection is bound */
	int  (*getmyname)(struct pcs_netconnect *nc, PCS_NET_ADDR_T * addr);

	/* launch connection state machine */
	void (*connect_start)(struct pcs_netconnect *nc);
};

struct pcs_netconnect_cops {
	/* handle_errors() and nc_complete() provides two-stage notification of
	   "connection done" event to the user: whenever network engine believes
	   that connection done, it firstly passes error status to the user by
	   calling handle_errors(), then, if it returns zero, creates brand-new
	   netio object and passes it the user by nc_complete()
	*/
	int  (*handle_errors)(struct pcs_netconnect *nc, int err);
	void (*nc_complete)(struct pcs_netconnect *nc, struct pcs_netio *netio);

	/* if handle_errors returned zero, but network engine cannot create new
	 * netio for some reasons, it calls sched_reconnect callback to give user
	 * a chance to schedule another connect attempt in future
	 */
	void (*sched_reconnect)(struct pcs_netconnect *nc, int err);

	/* network engine uses this callback to find out which pcs_process
	   to use for creating new netio, e.g. pcs_ioconn_init() needs proc.
	*/
	struct pcs_process *(*get_proc)(struct pcs_netconnect *nc);
};

struct pcs_netconnect {
	struct pcs_ioconn ioconn;
	unsigned int alloc_size;
	unsigned int hdr_size;
	void *private;

	/* transport methods */
	struct pcs_netconnect_tops *tops;

	/* callbacks */
	struct pcs_netconnect_cops *cops;
};

/*** netlisten -- represents network connection listener -- accepts incoming connections ***/

struct pcs_netlisten_tops {
	/* inquire current address to which the local endpoint of connection is bound */
	int   (*getmyname)(struct pcs_netlisten *nl, PCS_NET_ADDR_T * addr);
	/* launch listener state machine */
	int   (*listen_start)(struct pcs_netlisten *nl, int flags);
};

struct pcs_netlisten_cops {
	/* check_accept() and nl_accepted() provides two-stage notification of "incominig
	   connection accepted" event to the user: whenever network engine accepts
	   new connection, it firstly calls check_accept() callback asking user to check
	   its internal state and create user context associated with new connection; if
	   this goes fine, network engine will create brand-new netio and pass it along
	   with user context to user by calling nl_accepted() callback
	*/
	void *(*check_accept)(struct pcs_netlisten *nl);
	void  (*nl_accepted)(struct pcs_netlisten *nl, struct pcs_netio *netio, void *private);

	/* network engine uses this callback to find out which pcs_process
	   to use for creating new netio, e.g. pcs_ioconn_init() needs proc.
	*/
	struct pcs_process *(*get_proc)(struct pcs_netlisten *nl);
};

struct pcs_netlisten {
	struct pcs_ioconn ioconn;
	unsigned int alloc_size;
	unsigned int hdr_size;
	void *private;

	/* transport methods */
	struct pcs_netlisten_tops *tops;

	/* callbacks */
	struct pcs_netlisten_cops *cops;
};

#endif /* _PCS_NET_H_ */
