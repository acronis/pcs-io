/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __TIMER_H__
#define __TIMER_H__

#include "pcs_types.h"
#include "pcs_config.h"
#include "rbtree.h"
#include "std_list.h"
#include "pcs_atomic.h"
#include "pcs_thread.h"

typedef unsigned long long abs_time_t;
typedef long long time_diff_t;

struct pcs_process;
struct pcs_evloop;

#ifdef __WINDOWS__
struct timeval;
struct timezone;
PCS_API int gettimeofday(struct timeval * tp, struct timezone * tzp);
PCS_API abs_time_t filetime2ns(const FILETIME *ft);
PCS_API void ns2filetime(abs_time_t ns, FILETIME *filetime);
#endif /* __WINDOWS__ */

struct pcs_timer
{
	union {
		struct rb_node node;	/* used when expires != 0 */
		struct cd_list list;	/* used when expires == 0 */
	};
	abs_time_t expires;

	struct pcs_process *proc;
	pcs_atomic_ptr_t evloop;	/* not NULL when timer is armed */

	void (*function)(void *);
	void *data;
};

/*
 * NOTE: timers can be safely armed:
 * 1. before pcs_process started
 * 2. in evloop context only (after pcs_process started).
 * No remote timer arming from other threads supported
 */
PCS_API void init_timer(struct pcs_process *proc, struct pcs_timer *timer, void (*function)(void *), void *data);
PCS_API void mod_timer(struct pcs_timer *timer, time_diff_t ms);
PCS_API void del_timer_sync(struct pcs_timer *timer);
PCS_API int timer_pending(struct pcs_timer *timer);

/* The abs_time functions are expected to return monotonic time with arbitrary offset.
 * Note that in practice they may return slightly different values on different CPU cores.
 * So always use signed result while calculating difference between 2 time values (time_diff_t)
 * or call get_elapsed_time().
 */
PCS_API abs_time_t get_abs_time_ms(void);
PCS_API abs_time_t get_abs_time_us(void);
PCS_API abs_time_t get_real_time_ms(void);
PCS_API abs_time_t get_real_time_us(void);
PCS_API abs_time_t normalize_abs_time_us(abs_time_t t);

static inline abs_time_t get_elapsed_time(abs_time_t now, abs_time_t old)
{
	time_diff_t elapsed = now - old;
	return elapsed > 0 ? elapsed : 0;
}

/* ------------------- Internal API ----------------------- */

struct pcs_timer_tree
{
	struct rb_root	root;
	pthread_mutex_t	lock;
	struct pcs_timer *exec_timer;
	pthread_cond_t cond;
	int notify_cond;
};

void init_timers(struct pcs_timer_tree *);
void fini_timers(struct pcs_timer_tree *);
int check_timers(struct pcs_evloop *);
int get_timers_timeout(struct pcs_timer_tree *);
void abort_timers(struct pcs_timer_tree *);

#endif /* __TIMER_H__ */
