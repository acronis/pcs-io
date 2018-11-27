/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_iocp.h"
#include "pcs_poll.h"
#include "pcs_process.h"
#include "pcs_winapi.h"
#include "log.h"

void pcs_iocp_attach(struct pcs_process *proc, HANDLE handle, void *key)
{
	if (!CreateIoCompletionPort(handle, proc->iocp, (ULONG_PTR)key, 0)) {
		pcs_log_syserror(LOG_ERR, GetLastError(), "CreateIoCompletionPort failed");
		BUG();
	}
}

void pcs_iocp_cancel(HANDLE handle, struct pcs_iocp *iocp)
{
	if (CancelIoExPtr) {
		if (!CancelIoExPtr(handle, &iocp->overlapped) && GetLastError() != ERROR_NOT_FOUND)
			pcs_log_syserror(LOG_WARN, GetLastError(), "CancelIoEx failed");
	} else {
		if (!CancelIo(handle))
			pcs_log_syserror(LOG_WARN, GetLastError(), "CancelIo failed");
	}
}

void pcs_iocp_send(struct pcs_process *proc, struct pcs_iocp *iocp)
{
	if (!PostQueuedCompletionStatus(proc->iocp, 0, 0, &iocp->overlapped)) {
		pcs_log_syserror(LOG_ERR, GetLastError(), "PostQueuedCompletionStatus failed");
		BUG();
	}
}

int pcs_iocp_result(struct pcs_iocp *iocp)
{
	if (SUCCEEDED(iocp->overlapped.Internal))
		return (int)iocp->overlapped.InternalHigh;

	return -(int)RtlNtStatusToDosErrorPtr((NTSTATUS)iocp->overlapped.Internal);
}

int pcs_poll_init(struct pcs_process *proc)
{
	proc->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (!proc->iocp) {
		int err = GetLastError();
		pcs_log_syserror(LOG_ERR, err, "CreateIoCompletionPort failed");
		return -err;
	}
	return 0;
}

void pcs_poll_fini(struct pcs_process *proc)
{
	if (proc->iocp) {
		CloseHandle(proc->iocp);
		proc->iocp = NULL;
	}
}

void pcs_poll_wait(struct pcs_evloop *evloop, int timeout)
{
	HANDLE iocp = evloop->proc->iocp;
	OVERLAPPED_ENTRY *ev = evloop->events;

	BUG_ON(evloop->nr_events);

	if (GetQueuedCompletionStatusExPtr) {
		ULONG n;
		if (GetQueuedCompletionStatusExPtr(iocp, ev, PCS_MAX_EVENTS_NR, &n, timeout, FALSE)) {
			evloop->nr_events = n;
			return;
		}
	} else {
		ev->lpOverlapped = NULL;
		GetQueuedCompletionStatus(iocp, &ev->dwNumberOfBytesTransferred, &ev->lpCompletionKey, &ev->lpOverlapped, timeout);
		if (ev->lpOverlapped) {
			ev->Internal = ev->lpOverlapped->Internal;
			evloop->nr_events = 1;
			return;
		}
	}

	int err = GetLastError();
	if (err != WAIT_TIMEOUT)
		pcs_log_syserror(LOG_ERR, err, "GetQueuedCompletionStatus failed");
}

void pcs_poll_process_events(struct pcs_evloop *evloop)
{
	int i;
	for (i = 0; i < evloop->nr_events; i++) {
		struct pcs_iocp *iocp = container_of(evloop->events[i].lpOverlapped, struct pcs_iocp, overlapped);
		iocp->done(iocp);
	}

	evloop->nr_events = 0;
}
