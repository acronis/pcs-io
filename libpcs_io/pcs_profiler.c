/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <pthread.h>

#include "pcs_types.h"
#include "pcs_process.h"
#include "pcs_profiler.h"
#include "log.h"
#include "pcs_malloc.h"

int __pcs_profiler_enabled = 1;

#ifdef PCS_USE_PROFILER
#include <ucontext.h>
#include <syscall.h>
#include <execinfo.h> /* for backtraces */

#define PROFILER_PERIOD_MS	10
#define PROFILER_COLLECT_MS	(10*1000)
#define PROFILER_DUMP_MS	(1000)
#define PROFILER_MAXEV		(PROFILER_COLLECT_MS/PROFILER_PERIOD_MS)

/* Signal handler should be installed at the first profiler start
 * and uninstalled at the last profiler stop. */
static pthread_mutex_t proflock = PTHREAD_MUTEX_INITIALIZER;
static int profcount = 0;

static void profile_timer_set(struct pcs_profiler *prof, u64 nsec)
{
	prof->ptimer_active = nsec > 0;

	struct itimerspec val;
	val.it_interval.tv_sec = 0;
	val.it_interval.tv_nsec = nsec;
	val.it_value = val.it_interval;

	if (timer_settime(prof->ptimer, 0, &val, NULL))
		BUG();
}

static void dump_profile(struct pcs_evloop * evloop, int loglevel)
{
	int i;
	struct pcs_profiler *prof = evloop->prof;

	if (prof->ptimer_active)
		profile_timer_set(prof, 0);

	pcs_log(loglevel , "evloop #%d: WATCHDOG EVENTS=%d TOTAL=%d", evloop->id, prof->pptr, prof->ptotal);

	for (i = 0; i < prof->pptr; i++) {
		u64 pc;
		unsigned int overrun;

		pc = prof->pbuffer[i];

		overrun = pc >> 56;
		pc &=  ~(0xFFULL << 56);

#if defined(__LINUX__) || defined(__MAC__)
		void *array[1] = { (void *)(ULONG_PTR)pc };
		char **strings;
		strings = backtrace_symbols(array, 1);

		pcs_log(loglevel, "[%u] %s", overrun + 1, strings[0]);
		pcs_native_free(strings);
#else
		pcs_log(loglevel, "[%u] 0x%llx", overrun + 1, (unsigned long long)pc);
#endif

	}
}

static void profile_action(int signo, siginfo_t * si, void * ctx)
{
	ucontext_t * uc = ctx;
	struct pcs_evloop *evloop = si->si_ptr;
	struct pcs_profiler *prof = evloop->prof;
	int overrun = si->si_overrun;
	pcs_profiler_cb cb;
	u64 pc;

	if (prof->pactive == 0 && prof->ptimer_active) {
		profile_timer_set(prof, 0);
		return;
	}

#if defined(__aarch64__)
	pc = (u64)uc->uc_mcontext.pc;
#elif defined(__x86_64__)
	pc = (u64)uc->uc_mcontext.gregs[REG_RIP];
#elif defined(__i386__)
	pc = (u64)uc->uc_mcontext.gregs[REG_EIP];
#else
#error "Unsupported architecture"
#endif

	cb = prof->priv_cb;
	if (cb)
		cb(prof->priv_ctx, uc, overrun);

	prof->ptotal += overrun + 1;

	pc &= ~(0xFFULL << 56);
	if (overrun > 0xFF)
		overrun = 0xFF;
	pc |= ((u64)overrun << 56);

	if (prof->pptr < PROFILER_MAXEV)
		prof->pbuffer[prof->pptr++] = pc;
}

void pcs_profiler_start(struct pcs_evloop * evloop)
{
	struct sigevent ev;
	struct sigaction sa;

	if (!__pcs_profiler_enabled)
		return;

	struct pcs_profiler *prof = pcs_xzmalloc(sizeof(*prof));
	prof->pbuffer = pcs_xmalloc(8*PROFILER_MAXEV);
	prof->pptr = 0;
	prof->ptotal = 0;
	prof->pactive = 0;
	prof->ptimer_active = 0;
	evloop->prof = prof;

	pthread_mutex_lock(&proflock);
	if (profcount == 0) {
		memset(&sa, 0, sizeof(sa));
		sa.sa_flags = SA_SIGINFO|SA_RESTART;
		sa.sa_sigaction = profile_action;

		sigaction(PROFILER_SIGNO, &sa, NULL);
	}
	++profcount;
	pthread_mutex_unlock(&proflock);

	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_THREAD_ID;
	ev.sigev_signo = PROFILER_SIGNO;
	ev.sigev_value.sival_ptr = evloop;
	ev._sigev_un._tid = syscall(__NR_gettid);

	if (timer_create(CLOCK_MONOTONIC /*CLOCK_THREAD_CPUTIME_ID*/, &ev, &prof->ptimer))
		BUG();
}

void pcs_profiler_stop(struct pcs_evloop * evloop)
{
	struct pcs_profiler *prof = evloop->prof;

	if (!prof)
		return;

	prof->pactive = 0;
	prof->ptimer_active = 0;
	timer_delete(prof->ptimer);

	pthread_mutex_lock(&proflock);
	--profcount;
	if (profcount == 0)
		signal(PROFILER_SIGNO, SIG_DFL);
	pthread_mutex_unlock(&proflock);

	if (prof->pbuffer)
		pcs_free(prof->pbuffer);
	pcs_free(prof);
	evloop->prof = NULL;
}

/* This maybe needed to block profiler e.g. to give fork() a chance to complete w/o being interrupted by a timer signal and restarting constantly */
void pcs_profiler_block(struct pcs_evloop * evloop, sigset_t * oldmask)
{
	if (__pcs_profiler_enabled) {
		sigset_t mask;
		sigemptyset(&mask);
		sigaddset(&mask, PROFILER_SIGNO);
		pthread_sigmask(SIG_BLOCK, &mask, oldmask);
	}
}

void pcs_profiler_unblock(struct pcs_evloop * evloop, sigset_t * oldmask)
{
	if (__pcs_profiler_enabled)
		pthread_sigmask(SIG_SETMASK, oldmask, NULL);
}

void pcs_profiler_enter(struct pcs_evloop * evloop)
{
	struct pcs_profiler *prof = evloop->prof;

	if (!prof)
		return;

	if (prof->pactive)
		return;

	prof->pactive = 1;
	if (!prof->ptimer_active)
		profile_timer_set(prof, PROFILER_PERIOD_MS*1000*1000);

	prof->pptr = 0;
	prof->ptotal = 0;
}


void pcs_profiler_leave(struct pcs_evloop * evloop, int dump)
{
	struct pcs_profiler *prof = evloop->prof;

	if (!prof)
		return;

	if (!prof->pactive)
		return;

	prof->pactive = 0;

	if (dump || prof->ptotal > PROFILER_MAXEV || prof->ptotal > PROFILER_DUMP_MS / PROFILER_PERIOD_MS)
		dump_profile(evloop, LOG_ERR);
	else if (prof->pptr && pcs_log_level >= LOG_TRACE)
		dump_profile(evloop, LOG_TRACE);

	prof->pptr = 0;
	prof->ptotal = 0;
}

void * pcs_profiler_last_pc(struct pcs_evloop * evloop)
{
	struct pcs_profiler *prof = evloop->prof;

	if (!prof)
		return NULL;

	int last_ptr = prof->pptr;

	if (last_ptr > 0)
		return (void*)(unsigned long)(prof->pbuffer[last_ptr - 1] & ~(0xFFULL << 56));
	else
		return NULL;
}

void pcs_profiler_set_callback(struct pcs_evloop * evloop, pcs_profiler_cb cb, void* ctx)
{
	BUG_ON(evloop->prof->priv_cb);
	evloop->prof->priv_ctx = ctx;
	evloop->prof->priv_cb = cb;
}

#endif /* PCS_USE_PROFILER */
