/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_config.h"
#include "pcs_types.h"
#include "pcs_process.h"
#include "pcs_ioconn.h"
#include "pcs_signal.h"
#include "pcs_malloc.h"
#include "pcs_errno.h"
#include "pcs_poll.h"	/* for HAVE_KQUEUE */
#include "log.h"

#ifndef __WINDOWS__
#include <signal.h>
#endif
#include <string.h>
#ifdef PCS_ADDRESS_SANITIZER
#include <sanitizer/lsan_interface.h>
#endif

#if defined(__LINUX__) || defined(HAVE_KQUEUE)
struct pcs_signal {
	struct pcs_ioconn conn;
	pcs_sighandler_t handler;
	void *priv;
	struct cd_list list;
};


void pcs_signal_call_handler(struct pcs_ioconn *conn, int signal)
{
	struct pcs_signal *s = container_of(conn, struct pcs_signal, conn);
	struct pcs_process *proc = conn->proc;

	if (s->handler) {
		s->handler(proc, signal, s->priv);
	} else {
		pcs_log(LOG_INFO, "Got signal %d, terminating...", signal);
		pcs_process_terminate(proc);
	}
}
#endif /* __LINUX__ || HAVE_KQUEUE */

#if defined(__LINUX__)

#include "pcs_signalfd.h"
#include <unistd.h>

static void sfd_handle(struct pcs_ioconn *conn)
{
	struct signalfd_siginfo siginfo;
	ssize_t s = read(conn->fd, &siginfo, sizeof(siginfo));
	if (s < 0)
		pcs_fatal("Signalfd read error: %s", strerror(errno));
	if (s != sizeof(siginfo))
		pcs_fatal("Got %lu bytes from signalfd, but expected %lu",
			(unsigned long)s, (unsigned long)sizeof(siginfo));

	pcs_signal_call_handler(conn, siginfo.ssi_signo);
}

int pcs_signal_add_handler(struct pcs_process *proc, sigset_t *mask,
		pcs_sighandler_t handler, void *priv)
{
	int sfd = pcs_signalfd(-1, mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sfd < 0) {
		pcs_log_syserror(LOG_ERR, errno, "Failed to open signalfd");
		return -1;
	}

	struct pcs_signal *s = pcs_xmalloc(sizeof(*s));
	pcs_ioconn_init(proc, &s->conn);
	s->conn.data_ready = sfd_handle;
	s->conn.fd = sfd;
	s->conn.next_mask = POLLIN;
	s->handler = handler;
	s->priv = priv;
	cd_list_add(&s->list, &proc->sig_list);
	pcs_ioconn_register(&s->conn);

	return 0;
}

void pcs_signal_fini(struct pcs_process *proc)
{
	while (!cd_list_empty(&proc->sig_list)) {
		struct pcs_signal *s = cd_list_first_entry(&proc->sig_list, struct pcs_signal, list);
		cd_list_del(&s->list);
		pcs_ioconn_unregister(&s->conn);
	}
}

#elif defined(HAVE_KQUEUE)

int pcs_signal_add_handler(struct pcs_process *proc, sigset_t *mask, pcs_sighandler_t handler, void *priv)
{
	struct pcs_signal *s = pcs_xmalloc(sizeof(*s));
	pcs_ioconn_init(proc, &s->conn);
	s->handler = handler;
	s->priv = priv;
	cd_list_add(&s->list, &proc->sig_list);

	int res = 0, sig;
	for (sig = 1; sig <= NSIG; sig++) {
		if (sigismember(mask, sig) <= 0)
			continue;

		struct kevent ev = {.ident = sig, .filter = EVFILT_SIGNAL, .flags = EV_ADD | EV_CLEAR, .udata = &s->conn};
		if (kevent(proc->kqueue, &ev, 1, NULL, 0, NULL)) {
			pcs_log_syserror(LOG_ERR, errno, "Failed to add event for signal %d to kqueue", sig);
			res = -1;
		}
	}
	return res;
}

void pcs_signal_fini(struct pcs_process *proc)
{
	while (!cd_list_empty(&proc->sig_list)) {
		struct pcs_signal *s = cd_list_first_entry(&proc->sig_list, struct pcs_signal, list);
		cd_list_del(&s->list);
		pcs_free(s);
	}
}

#else

int pcs_signal_add_handler(struct pcs_process *proc, sigset_t *mask,
		pcs_sighandler_t handler, void *priv)
{
	return 0;
}

void pcs_signal_fini(struct pcs_process *proc)
{
}

#endif

void pcs_signal_block(sigset_t *mask)
{
#ifndef __WINDOWS__
	/* Block signals so that they aren't handled
	 * according to their default dispositions */
	BUG_ON(pthread_sigmask(SIG_BLOCK, mask, NULL));
#endif
}

int pcs_signal_set_defaults(struct pcs_process *proc)
{
#ifndef __WINDOWS__
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	pcs_signal_block(&mask);
	if (pcs_signal_add_handler(proc, &mask, NULL, NULL) < 0)
		return -1;
#endif
	return 0;
}

int pcs_signal_set_fatal_handlers(void)
{
#if defined(__LINUX__) || defined(__MAC__)
	struct sigaction sa;
	stack_t ss;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = pcs_log_fatal_sighandler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NODEFER | SA_RESETHAND | SA_SIGINFO;

	/* create alternative stack if possible */
	ss.ss_sp = pcs_xmalloc(2 * SIGSTKSZ);
#ifdef PCS_ADDRESS_SANITIZER
	__lsan_ignore_object(ss.ss_sp);
#endif
	ss.ss_flags = 0;
	ss.ss_size = 2 * SIGSTKSZ;

	if (sigaltstack(&ss, NULL) == 0)
		sa.sa_flags |= SA_ONSTACK;
	else {
		pcs_log(LOG_WARN, "sigaltstack() failed: %s\n", strerror(errno));
		pcs_free(ss.ss_sp);
	}

	/* set handlers whenever possible */
	if (sigaction(SIGILL, &sa, NULL) < 0)
		pcs_log(LOG_WARN, "sigaction(SIGILL) failed: %s\n", strerror(errno));
	if (sigaction(SIGFPE, &sa, NULL) < 0)
		pcs_log(LOG_WARN, "sigaction(SIGFPE) failed: %s\n", strerror(errno));
	if (sigaction(SIGSEGV, &sa, NULL) < 0)
		pcs_log(LOG_WARN, "sigaction(SIGSEGV) failed: %s\n", strerror(errno));
	if (sigaction(SIGABRT, &sa, NULL) < 0)
		pcs_log(LOG_WARN, "sigaction(SIGABRT) failed: %s\n", strerror(errno));
	if (sigaction(SIGBUS, &sa, NULL) < 0)
		pcs_log(LOG_WARN, "sigaction(SIGBUS) failed: %s\n", strerror(errno));
#elif defined(__WINDOWS__)
	old_fatal_handler = SetUnhandledExceptionFilter(pcs_log_fatal_sighandler);
#endif
	return 0;
}
