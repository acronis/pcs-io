/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_PROFILER_H_
#define _PCS_PROFILER_H_ 1

#include "pcs_config.h"
#include "pcs_types.h"

#if defined(HAVE_POSIX_TIMER) && !defined(PCS_PROFILER_DISABLE)
#define PCS_USE_PROFILER 1
#include <time.h>
#include <signal.h>
#endif


#define PROFILER_SIGNO          35

struct pcs_evloop;
typedef void (*pcs_profiler_cb)(void* ctx, void* uc, int overrun);

struct pcs_profiler
{
#ifdef PCS_USE_PROFILER
	timer_t		ptimer;
	u64		*pbuffer;
	int		pptr;
	int		ptotal;
	int		pactive;
	volatile int	ptimer_active;
	volatile pcs_profiler_cb priv_cb;
	void* volatile	priv_ctx;
#else
	int		to_make_compiler_happy;
#endif
};

#ifdef PCS_USE_PROFILER

extern int __pcs_profiler_enabled;

static inline void pcs_profile_enable(int enable)
{
	__pcs_profiler_enabled = enable;
}

void pcs_profiler_start(struct pcs_evloop * evloop);
void pcs_profiler_stop(struct pcs_evloop * evloop);
void pcs_profiler_enter(struct pcs_evloop * evloop);
void pcs_profiler_leave(struct pcs_evloop * evloop, int dump);
void pcs_profiler_block(struct pcs_evloop * evloop, sigset_t * oldmask);
void pcs_profiler_unblock(struct pcs_evloop * evloop, sigset_t * oldmask);
void * pcs_profiler_last_pc(struct pcs_evloop * evloop);
void pcs_profiler_set_callback(struct pcs_evloop * evloop, pcs_profiler_cb cb, void* ctx);

#else
static inline void pcs_profile_enable(int enable) {};
static inline void pcs_profiler_start(struct pcs_evloop * evloop) {};
static inline void pcs_profiler_stop(struct pcs_evloop * evloop) {};
static inline void pcs_profiler_enter(struct pcs_evloop * evloop) {};
static inline void pcs_profiler_leave(struct pcs_evloop * evloop, int dump) {};
/* avoid definition of sigset_t */
#define pcs_profiler_block(evloop, oldmask) do {(void)oldmask;} while (0)
#define pcs_profiler_unblock(evloop, oldmask) do {(void)oldmask;} while (0)
static inline void *pcs_profiler_last_pc(struct pcs_evloop * evloop) { return NULL; };
static inline void pcs_profiler_set_callback(struct pcs_evloop * evloop, pcs_profiler_cb cb, void* ctx) {}
#endif


#endif /* _PCS_PROFILER_H_ */
