/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_WATCHDOG_H_
#define _PCS_WATCHDOG_H_ 1

#include "pcs_config.h"

#if defined(__linux__) && !defined(PCS_WATCHDOG_DISABLE) && !defined(PCS_ADDR_SANIT)
#define PCS_USE_WATCHDOG 1
#endif

#ifdef PCS_USE_WATCHDOG
#include <time.h>
#include "pcs_thread.h"
#endif

#define PCS_LOOP_WATCHDOG_TIME (15*1000)

struct pcs_evloop;
struct pcs_watchdog;

#ifdef PCS_USE_WATCHDOG

struct pcs_watchdog
{
	/* For pcs_process */
	pcs_thread_t	wd_thr;
	pthread_mutex_t	wd_mutex;
	pthread_cond_t	wd_wake;
	int		wd_run;

	/* For pcs_evloop */
	int		wd_poll_count;
	int		wd_poll_checked;
	abs_time_t	wd_last_activity;
	abs_time_t	wd_accounted;
	abs_time_t	wd_inactive_total;
};

void pcs_watchdog_start(struct pcs_process *proc);
void pcs_watchdog_stop(struct pcs_process *proc);
void pcs_watchdog_init_evloop(struct pcs_evloop *evloop);
void pcs_watchdog_enter_poll(struct pcs_evloop *evloop);
void pcs_watchdog_leave_poll(struct pcs_evloop *evloop);

#else /* PCS_USE_WATCHDOG */

static inline void pcs_watchdog_start(struct pcs_process *proc) {}
static inline void pcs_watchdog_stop(struct pcs_process *proc) {}
static inline void pcs_watchdog_init_evloop(struct pcs_evloop *evloop) {}
static inline void pcs_watchdog_enter_poll(struct pcs_evloop *evloop) {}
static inline void pcs_watchdog_leave_poll(struct pcs_evloop *evloop) {}

#endif /* PCS_USE_WATCHDOG */

#endif /* _PCS_WATCHDOG_H_ */
