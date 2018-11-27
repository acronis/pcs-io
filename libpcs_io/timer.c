/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_types.h"

#ifdef __WINDOWS__
#include "pcs_sock.h" /* windows is ugly: winsock2.h declares timeval */
#else
#include <unistd.h>
#include <sys/time.h>
#endif

#include <stdlib.h>
#include <stddef.h>
#include <time.h>

#include "timer.h"
#include "log.h"
#include "pcs_process.h"
#include "pcs_profiler.h"
#include "pcs_config.h"
#include "pcs_winapi.h"

static time_t time_poison;
static abs_time_t time_skew_mask;

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 2
#endif

#ifdef __WINDOWS__
/* Use clock_gettime() implementation based on performance counters for monotonic clocks */
#ifndef _POSIX_MONOTONIC_CLOCK
#define _POSIX_MONOTONIC_CLOCK 1
#endif

// Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

/* FILETIME from Epoch to now in 100 ns intervals */
static ULARGE_INTEGER xgetfiletime(void)
{
	ULARGE_INTEGER current_time;
	FILETIME current_time_ft;
	/* GetSystemTimePreciseAsFileTime WinAPI function hase precision 100 ns instead of old GetSystemTime* functions with precision 16 ms.
	 * But that function persists starting with Windows 8/Windows Server 2012 */
	if (!GetSystemTimePreciseAsFileTimePtr)
		GetSystemTimeAsFileTime(&current_time_ft);
	else
		GetSystemTimePreciseAsFileTimePtr(&current_time_ft);

	current_time.LowPart = current_time_ft.dwLowDateTime;
	current_time.HighPart = current_time_ft.dwHighDateTime;
	current_time.QuadPart -= EPOCH;

	return current_time;
}

int gettimeofday(struct timeval * tp, struct timezone * tzp)
{
	ULARGE_INTEGER file_time = xgetfiletime();
	file_time.QuadPart /= 10; // convert to microseconds

	tp->tv_sec  = (long)(file_time.QuadPart / 1000000);
	tp->tv_usec = (long)(file_time.QuadPart % 1000000);
	return 0;
}

abs_time_t filetime2ns(const FILETIME * file_time)
{
	abs_time_t time;
	time =  ((abs_time_t)file_time->dwLowDateTime);
	time += ((abs_time_t)file_time->dwHighDateTime) << 32;
	time -= EPOCH;
	return time * 100;
}

void ns2filetime(abs_time_t ns, FILETIME *file_time)
{
	const abs_time_t ticks = ns / 100 + EPOCH;
	file_time->dwLowDateTime = (DWORD)ticks;
	file_time->dwHighDateTime = (DWORD)(ticks >> 32);
}

/* http://patchwork.openvswitch.org/patch/3172/ */
int clock_gettime(clockid_t id, struct timespec *ts)
{
	if (id == CLOCK_MONOTONIC) {
		static LARGE_INTEGER freq;
		LARGE_INTEGER count;
		unsigned long long int ns;

		/* QueryUnbiasedInterruptTime WinAPI function doesn't count hibernate/sleep time,
		 * but it persists starting with Windows 7/Windows Server 2008 R2.
		 * The result time is in 100 ns intervals */
		if (QueryUnbiasedInterruptTimePtr && QueryUnbiasedInterruptTimePtr((PULONGLONG)&ns)) {
			ts->tv_sec = (time_t)(ns / 10000000);
			ts->tv_nsec = (long)((ns % 10000000) * 100);
			return 0;
		}

		if (!freq.QuadPart) {
			/* Number of counts per second. */
			QueryPerformanceFrequency(&freq);
		}
		/* Total number of counts from a starting point. */
		QueryPerformanceCounter(&count);

		/* Total nano seconds from a starting point. */
		ns = (unsigned long long)((double)count.QuadPart / freq.QuadPart * 1000000000);

		ts->tv_sec = count.QuadPart / freq.QuadPart;
		ts->tv_nsec = ns % 1000000000;
	} else if (id == CLOCK_REALTIME) {
		/* FILETIME from Epoch to now in 100 ns intervals */
		ULARGE_INTEGER current_time = xgetfiletime();
		ts->tv_sec = (time_t)(current_time.QuadPart / 10000000);
		ts->tv_nsec = (long)((current_time.QuadPart % 10000000) * 100);
	} else {
		return -1;
	}

	return 0;
}
#endif /* __WINDOWS__ */

static void __noinline poison_abs_time(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	time_t p = tv.tv_usec;

	do {
		p = (1664525 * p + 1013904223) & 0x7FFFFFFF;
	} while (p == 0);

	time_poison = p;

	const char* s = getenv("PSTORAGE_CLK_SKEW");
	if (s) {
		int bits = atoi(s);
		if (bits > 0)
			time_skew_mask = (1ULL << bits) - 1;
	}
}

void init_timers(struct pcs_timer_tree *timers)
{
	rb_init(&timers->root);
	pthread_mutex_init(&timers->lock, NULL);
	pthread_cond_init(&timers->cond, NULL);
	timers->exec_timer = NULL;
	timers->notify_cond = 0;
}

void fini_timers(struct pcs_timer_tree *timers)
{
	BUG_ON(!rb_empty(&timers->root));
	pthread_mutex_destroy(&timers->lock);
	pthread_cond_destroy(&timers->cond);
}

abs_time_t get_abs_time_us(void)
{
	abs_time_t t;
	if (time_poison == 0)
		poison_abs_time();

#if defined(_POSIX_MONOTONIC_CLOCK) && (_POSIX_MONOTONIC_CLOCK >= 0)
	struct timespec ts;
	BUG_ON(clock_gettime(CLOCK_MONOTONIC, &ts));
	t = (abs_time_t)(ts.tv_sec + time_poison) * 1000000 + ts.tv_nsec / 1000;
#else
	struct timeval tv;
	gettimeofday(&tv, NULL);
	t = (abs_time_t)(tv.tv_sec + time_poison) * 1000000 + tv.tv_usec;
#endif
	return t ^ time_skew_mask;
}

abs_time_t normalize_abs_time_us(abs_time_t t)
{
	return t - (abs_time_t)(time_poison) * 1000000;
}

abs_time_t get_abs_time_ms(void)
{
	return get_abs_time_us() / 1000;
}

abs_time_t get_real_time_ms(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (abs_time_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

abs_time_t get_real_time_us(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (abs_time_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

void init_timer(struct pcs_process* proc, struct pcs_timer *timer, void (*function)(void *), void *data)
{
	timer->function = function;
	timer->data = data;
	timer->expires = 0;
	timer->proc = proc;
	pcs_atomic_ptr_store(&timer->evloop, NULL);
	cd_list_init(&timer->list);
}

static inline int timer_cmp(struct rb_node *node, ULONG_PTR key)
{
	struct pcs_timer *timer = rb_entry(node, struct pcs_timer, node);
	abs_time_t *t = (abs_time_t *)key;

	if (timer->expires < *t)
		return 1;
	if (timer->expires > *t)
		return -1;
	return 0;
}

static void __mod_timer(struct pcs_timer *timer, struct pcs_timer_tree *timers, abs_time_t expires)
{
	if (timer->expires) {
		/* if armed, remove first */
		rb_delete(&timers->root, &timer->node);
	} else {
		cd_list_del(&timer->list);
	}

	timer->expires = expires;
	rb_insert_node(&timers->root, &timer->node, timer_cmp, (ULONG_PTR)&timer->expires);
}

static void __del_timer(struct pcs_timer *timer, struct pcs_timer_tree *timers)
{
	if (timer->expires) {
		/* if armed, remove first */
		rb_delete(&timers->root, &timer->node);
		timer->expires = 0;
		cd_list_init(&timer->list);
	} else {
		cd_list_del_init(&timer->list);
	}
}

static void __set_timer_evloop(struct pcs_timer *timer, struct pcs_evloop *evloop)
{
	pcs_wmb();
	pcs_atomic_ptr_store(&timer->evloop, evloop);
}

void mod_timer(struct pcs_timer *timer, time_diff_t timeout)
{
	struct pcs_evloop *this_evloop = pcs_current_evloop;
	abs_time_t now;

	if (unlikely(!this_evloop)) {
		BUG_ON(pcs_process_is_running(timer->proc));
		this_evloop = &timer->proc->evloops[0];
		now = get_abs_time_ms();
	} else {
		now = this_evloop->last_abs_time_ms;
	}

	abs_time_t expires = timeout > 0 ? now + timeout : now;

	if (this_evloop->proc->nr_evloops == 1) {
		/* no sync for single-threaded app */
		__mod_timer(timer, &this_evloop->timers, expires);
		return;
	}

restart:;
	struct pcs_evloop *evloop = pcs_atomic_ptr_cas(&timer->evloop, NULL, this_evloop);
	if (!evloop)
		evloop = this_evloop;

	for (;;) {
		pthread_mutex_lock(&evloop->timers.lock);
		struct pcs_evloop *actual_evloop = pcs_atomic_ptr_load(&timer->evloop);
		if (unlikely(actual_evloop != evloop)) {
			pthread_mutex_unlock(&evloop->timers.lock);
			if (!actual_evloop)
				goto restart;

			evloop = actual_evloop;
			continue;
		}

		if (likely(evloop == this_evloop) || unlikely(evloop->timers.exec_timer == timer)) {
			/* If timer function is running in another eventloop,
			 * reschedule timer in the same eventloop to avoid waiting for its completion */
			 __mod_timer(timer, &evloop->timers, expires);
		 	pthread_mutex_unlock(&evloop->timers.lock);
			break;
		}

		__del_timer(timer, &evloop->timers);
		__set_timer_evloop(timer, this_evloop);
		pthread_mutex_unlock(&evloop->timers.lock);
		evloop = this_evloop;
	}
}

void del_timer_sync(struct pcs_timer *timer)
{
	struct pcs_evloop *this_evloop = pcs_current_evloop;

	if (unlikely(!this_evloop)) {
		BUG_ON(pcs_process_is_running(timer->proc));
		this_evloop = &timer->proc->evloops[0];
	}

	if (this_evloop->proc->nr_evloops == 1) {
		/* no sync for single-threaded app */
		__del_timer(timer, &this_evloop->timers);
		return;
	}

	struct pcs_evloop *evloop = pcs_atomic_ptr_load(&timer->evloop);
	if (!evloop)
		return;

	pthread_mutex_lock(&evloop->timers.lock);
	for (;;) {
		struct pcs_evloop *actual_evloop = pcs_atomic_ptr_load(&timer->evloop);
		if (unlikely(actual_evloop != evloop)) {
			if (!actual_evloop)
				break;

			pthread_mutex_unlock(&evloop->timers.lock);
			evloop = actual_evloop;
			pthread_mutex_lock(&evloop->timers.lock);
			continue;
		}

		if (likely(evloop->timers.exec_timer != timer)) {
			__del_timer(timer, &evloop->timers);
			__set_timer_evloop(timer, NULL);
			break;
		}

		if (likely(evloop == this_evloop)) {
			/* del_timer_sync() is called recursively from timer callback.
			 * Do update timer->evloop, it will be done by exec_timer() later */
			__del_timer(timer, &evloop->timers);
			break;
		}

		evloop->timers.notify_cond++;
		pthread_cond_wait(&evloop->timers.cond, &evloop->timers.lock);
		evloop->timers.notify_cond--;
	}
	pthread_mutex_unlock(&evloop->timers.lock);
}

int timer_pending(struct pcs_timer *timer)
{
	return timer->expires != 0;
}

static int __get_timers_timeout(struct pcs_timer_tree *timers, abs_time_t now)
{
	struct rb_node *node = rb_first(&timers->root);
	if (!node)
		return PCS_LOOP_WATCHDOG_TIME/2;

	struct pcs_timer *timer = rb_entry(node, struct pcs_timer, node);
	abs_time_t timeout = get_elapsed_time(timer->expires, now);
	return timeout < PCS_LOOP_WATCHDOG_TIME/2 ? (int)timeout : PCS_LOOP_WATCHDOG_TIME/2;
}

/* returns ms to nearest timer or -1 if no timers */
int get_timers_timeout(struct pcs_timer_tree *timers)
{
	pthread_mutex_lock(&timers->lock);
	int timeout = __get_timers_timeout(timers, get_abs_time_ms());
	pthread_mutex_unlock(&timers->lock);

	return timeout;
}

static void exec_timer(struct pcs_timer_tree *timers, struct pcs_timer *timer)
{
	timers->exec_timer = timer;
	pthread_mutex_unlock(&timers->lock);

	timer->function(timer->data);

	pthread_mutex_lock(&timers->lock);
	timers->exec_timer = NULL;
	if (timers->notify_cond)
		pthread_cond_broadcast(&timers->cond);
}

/* returns ms to nearest timer or -1 if no timers */
int check_timers(struct pcs_evloop *evloop)
{
	struct rb_node *node;
	struct pcs_timer *timer;
	abs_time_t now = evloop->last_abs_time_ms;
	struct cd_list list = CD_LIST_INIT(list);

	pthread_mutex_lock(&evloop->timers.lock);

	/* 1. move all expired timers to list to avoid inf loop over 0 timers */
	node = rb_first(&evloop->timers.root);
	while (node) {
		timer = rb_entry(node, struct pcs_timer, node);
		BUG_ON(timer->proc != evloop->proc);

		if (timer->expires > now)
			break;

		node = rb_next(node);

		rb_delete(&evloop->timers.root, &timer->node);
		timer->expires = 0;
		cd_list_add_tail(&timer->list, &list);
	}

	/* 2. fire all expired/isolated timers */
	while (!cd_list_empty(&list)) {
		timer = cd_list_first_entry(&list, struct pcs_timer, list);
		cd_list_del_init(&timer->list);

		exec_timer(&evloop->timers, timer);
	}

	/* We need to extract first entry again since new timers may
	 * be added on firing timers at stage (2)
	 */
	int timeout = __get_timers_timeout(&evloop->timers, now);
	pthread_mutex_unlock(&evloop->timers.lock);

	return timeout;
}

void abort_timers(struct pcs_timer_tree *timers)
{
	/* Cannot really do anything about them. */
	rb_init(&timers->root);
}
