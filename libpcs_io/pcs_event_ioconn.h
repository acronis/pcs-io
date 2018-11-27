/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCS_EVENT_H__
#define __PCS_EVENT_H__

#include "pcs_ioconn.h"
#include "pcs_iocp.h"
#include "pcs_process.h"

/*
 * PCS event ioconn is a method to send any kind of manual notifications to eventloop from other threads,
 * e.g. sync_io threads, file_jobs etc.
 */

struct pcs_event_ioconn
{
#ifndef __WINDOWS__
	struct pcs_ioconn ioconn;
	int send_event_fd;
#else
	struct pcs_iocp iocp;
	struct pcs_process *proc;
#endif
	void (*data_ready)(void *priv);
	void *priv;
};

int pcs_event_ioconn_init(struct pcs_process *proc, struct pcs_event_ioconn **event, void (*data_ready)(void *priv), void *priv);
void pcs_event_ioconn_close(struct pcs_event_ioconn * event);

/* wakeup eventloop on event */
void pcs_event_ioconn_wakeup(struct pcs_event_ioconn * event);

#endif /* __PCS_EVENT_H__ */
