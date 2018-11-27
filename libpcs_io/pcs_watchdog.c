/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <execinfo.h>

#include "pcs_types.h"
#include "pcs_process.h"
#include "pcs_watchdog.h"
#include "pcs_malloc.h"
#include "pcs_thread.h"
#include "log.h"

#ifdef PCS_USE_WATCHDOG

__no_sanitize_thread static int get_poll_count(struct pcs_watchdog *wd)
{
	return wd->wd_poll_count;
}

static void dump_kstack(struct pcs_evloop* evloop)
{
	struct pcs_watchdog *wd = evloop->wd;
	char buf[256];
	FILE * stack_fp;
	abs_time_t now = get_abs_time_ms();
	void * last_pc[1];

	wd->wd_inactive_total += now - wd->wd_last_activity - wd->wd_accounted;
	wd->wd_accounted = now - wd->wd_last_activity;

	snprintf(buf, sizeof(buf), "/proc/%lu/stack", evloop->thr_id);
	stack_fp = fopen(buf, "r");
	if (stack_fp == NULL)
		pcs_log(LOG_ERR, "pcs watchdog failed to open %s: err=%d", buf, errno);

	pcs_log(LOG_ERR, "pcs evloop #%d is inactive for %u msecs (%u)",
		evloop->id,
		(unsigned)(now - wd->wd_last_activity),
		(unsigned)(get_abs_time_ms() - now));

	last_pc[0] = pcs_profiler_last_pc(evloop);
	if (last_pc[0]) {
		char ** s = backtrace_symbols(last_pc, sizeof(last_pc));
		pcs_log(LOG_ERR, "Last PC: %s", s[0]);
		pcs_native_free(s);
	}

	if (stack_fp) {
		while (fgets(buf, sizeof(buf) - 1, stack_fp)) {
			buf[sizeof(buf) - 1] = 0;
			pcs_log(LOG_ERR|LOG_NONL, "%s", buf);
		}
		if (ferror(stack_fp))
			pcs_log(LOG_ERR, "Stack is unavailable: err=%d", errno);
		fclose(stack_fp);
	}

	stack_fp = fopen("/proc/meminfo", "r");
	if (stack_fp == NULL)
		return;

	while (fgets(buf, sizeof(buf) - 1, stack_fp)) {
		buf[sizeof(buf) - 1] = 0;
		pcs_log(LOG_ERR|LOG_NONL, "%s", buf);
	}
	fclose(stack_fp);

	stack_fp = fopen("/proc/vz/latency", "r");
	if (stack_fp == NULL)
		return;

	while (fgets(buf, sizeof(buf) - 1, stack_fp)) {
		buf[sizeof(buf) - 1] = 0;
		pcs_log(LOG_ERR|LOG_NONL, "%s", buf);
	}
	fclose(stack_fp);

	stack_fp = popen("ps axv", "r");
	if (stack_fp == NULL)
		return;

	while (fgets(buf, sizeof(buf) - 1, stack_fp)) {
		buf[sizeof(buf) - 1] = 0;
		pcs_log(LOG_ERR|LOG_NONL, "%s", buf);
	}
	pclose(stack_fp);
}

static void do_monitor(struct pcs_evloop * evloop)
{
	struct pcs_watchdog *wd = evloop->wd;
	int poll_count;

	poll_count = get_poll_count(wd);

	if (poll_count != wd->wd_poll_checked || (poll_count & 1)) {
		wd->wd_poll_checked = poll_count;
		wd->wd_last_activity = get_abs_time_ms();
		wd->wd_accounted = 0;
		return;
	}

	dump_kstack(evloop);
}

static pcs_thread_ret_t watchdog_thread(void * arg)
{
	struct pcs_process *proc = arg;
	struct pcs_watchdog *wd = proc->evloops[0].wd;

	pcs_thread_setname("watchdog");

	pthread_mutex_lock(&wd->wd_mutex);
	abs_time_t last = get_abs_time_ms();
	while (wd->wd_run) {
		u32 i;
		for (i = 0; i < proc->nr_evloops; i++)
			do_monitor(&proc->evloops[i]);
		pcs_thread_cond_timedwait(&wd->wd_wake, &wd->wd_mutex, 1000);
		abs_time_t now = get_abs_time_ms();
		abs_time_t elapsed = get_elapsed_time(now, last);
		if (elapsed >= 2000)
			pcs_log(LOG_ERR, "monitor process '%s' executed %llu ms", proc->name, (llu)elapsed);
		last = now;
	}
	pthread_mutex_unlock(&wd->wd_mutex);
	return 0;
}

void pcs_watchdog_init_evloop(struct pcs_evloop *evloop)
{
	struct pcs_watchdog *wd = pcs_xzmalloc(sizeof(*wd));
	wd->wd_poll_count = 0;
	wd->wd_poll_checked = -1;
	wd->wd_last_activity = get_abs_time_ms();
	wd->wd_accounted = 0;
	wd->wd_inactive_total = 0;
	evloop->wd = wd;
}

void pcs_watchdog_start(struct pcs_process *proc)
{
	struct pcs_watchdog *wd = proc->evloops[0].wd;
	if (!wd)
		return;

	pthread_mutex_init(&wd->wd_mutex, NULL);
	pthread_cond_init(&wd->wd_wake, NULL);
	wd->wd_run = 1;

	if (pcs_thread_create(&wd->wd_thr, NULL, watchdog_thread, proc))
		BUG();
}

void pcs_watchdog_stop(struct pcs_process *proc)
{
	struct pcs_watchdog *wd = proc->evloops[0].wd;
	if (!wd)
		return;

	pthread_mutex_lock(&wd->wd_mutex);
	wd->wd_run = 0;
	pthread_cond_signal(&wd->wd_wake);
	pthread_mutex_unlock(&wd->wd_mutex);

	pcs_thread_join(wd->wd_thr);

	u32 i;
	for (i = 0; i < proc->nr_evloops; i++) {
		pcs_free(proc->evloops[i].wd);
		proc->evloops[i].wd = NULL;
	}
}

void pcs_watchdog_enter_poll(struct pcs_evloop * evloop)
{
	if (evloop->wd)
		evloop->wd->wd_poll_count++;
}

void pcs_watchdog_leave_poll(struct pcs_evloop * evloop)
{
	if (evloop->wd)
		evloop->wd->wd_poll_count++;
}

#endif /* PCS_USE_WATCHDOG */
