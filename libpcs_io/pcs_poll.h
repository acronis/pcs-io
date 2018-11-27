/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCS_POLL_H__
#define __PCS_POLL_H__

#include "pcs_types.h"

#ifdef __LINUX__
#include <poll.h>
#include <sys/epoll.h>
#define HAVE_EPOLL	1

#ifndef POLLRDHUP
#define POLLRDHUP	0x2000
#endif
#endif

#ifdef __MAC__
#include <poll.h>
#include <sys/event.h>
#define HAVE_KQUEUE	1

#define POLLRDHUP	0
#define EPOLLET		(1 << 31)
#endif

#ifdef __SUN__
#include <port.h>

#define POLLRDHUP	0
#define EPOLLET		0
#endif

struct pcs_process;
struct pcs_evloop;
struct pcs_ioconn;
struct pcs_co_file;

int pcs_poll_init(struct pcs_process *proc);
void pcs_poll_fini(struct pcs_process *proc);

int pcs_poll_ctl(struct pcs_process *proc, struct pcs_ioconn *conn);
void pcs_poll_wait(struct pcs_evloop *evloop, int timeout);
void pcs_poll_process_events(struct pcs_evloop *evloop);

void pcs_poll_file_init(struct pcs_co_file *file);
void pcs_poll_file_fini(struct pcs_co_file *file);
void pcs_poll_file_begin(struct pcs_co_file *file, int mask);

#endif
