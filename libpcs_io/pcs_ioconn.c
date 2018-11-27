/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_types.h"
#include "pcs_malloc.h"
#include "pcs_ioconn.h"
#include "pcs_poll.h"
#include "pcs_process.h"
#include "log.h"

#include <unistd.h>

static void hup_callback(struct pcs_ioconn * conn)
{
}

void pcs_ioconn_close(struct pcs_ioconn * conn)
{
	if (conn->fd >= 0) {
		close(conn->fd);
		conn->fd = -1;
	}
}

void pcs_ioconn_destruct(struct pcs_ioconn * conn)
{
	pcs_ioconn_close(conn);
	pcs_free(conn);
}

void pcs_ioconn_init(struct pcs_process * proc, struct pcs_ioconn * conn)
{
	cd_list_init(&conn->list);
	pcs_ioconn_reset(conn);
	conn->dead = 0;
	conn->actual_mask = 0;
	conn->next_mask = 0;
	conn->proc = proc;
	conn->data_ready = conn->write_space = conn->error_report = hup_callback;
	conn->destruct = pcs_ioconn_destruct;
}

void pcs_ioconn_register(struct pcs_ioconn * conn)
{
	cd_list_add_tail(&conn->list, &conn->proc->ioconns);

	conn->actual_mask = 0;
	if (conn->next_mask)
		pcs_ioconn_schedule(conn);
}

void pcs_ioconn_unregister(struct pcs_ioconn * conn)
{
	if (conn->dead)
		return;

	conn->data_ready = conn->write_space = conn->error_report = hup_callback;

	conn->next_mask = 0;
	pcs_ioconn_schedule(conn);

	cd_list_del(&conn->list);
	conn->dead = 1;

	if (!conn->destruct)
		return;

	struct pcs_process *proc = conn->proc;
	if (!pcs_process_is_running(proc)) {
		conn->destruct(conn);
	} else {
		cd_list_add_tail(&conn->list, &proc->kill_list);
		pcs_job_wakeup(&proc->kill_ioconn_job);
	}
}

void pcs_ioconn_schedule(struct pcs_ioconn * conn)
{
	if (conn->actual_mask == conn->next_mask || conn->dead)
		return;

	struct pcs_process *proc = conn->proc;

	int err = pcs_poll_ctl(proc, conn);
	if (err) {
		pcs_log(LOG_ERR, "epoll error=%d %08x->%08x", err, conn->actual_mask, conn->next_mask);
		BUG();
	}

	if (conn->actual_mask == 0)
		proc->n_ioconns++;
	else if (conn->next_mask == 0)
		proc->n_ioconns--;

	conn->actual_mask = conn->next_mask;
}

/* called via pcs_ioconn_unregister -> proc.kill_ioconn_job job */
void ioconn_kill_all(void * arg)
{
	struct pcs_process * proc = (struct pcs_process *)arg;
	struct pcs_ioconn * conn;

	while (!cd_list_empty(&proc->kill_list)) {
		conn = cd_list_first_entry(&proc->kill_list, struct pcs_ioconn, list);
		cd_list_del(&conn->list);
		conn->destruct(conn);
	}
}
