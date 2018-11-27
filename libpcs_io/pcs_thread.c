/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_types.h"
#include "pcs_config.h"
#include "pcs_malloc.h"
#include "pcs_thread.h"
#include "timer.h"
#include "bug.h"
#include "log.h"

#ifndef __WINDOWS__
#include <sys/time.h>
#include <errno.h>
#endif

int pcs_thread_create(pcs_thread_t * thread, const pcs_thread_attr_t * attr, pcs_thread_ret_t (*start_routine)(void *), void * arg)
{
	pthread_attr_t pattr;

	if (pthread_attr_init(&pattr))
		return -1;

	if (attr && attr->stack_size && pthread_attr_setstacksize(&pattr, attr->stack_size)) {
#ifdef __WINDOWS__
		int winerr = GetLastError();
		pcs_log(LOG_ERR, "pthread_attr_setstacksize %lu failed: errno=%d err=%d", attr->stack_size, errno, winerr);
#else
		pcs_log(LOG_ERR, "pthread_attr_setstacksize %lu failed: errno=%d", attr->stack_size, errno);
#endif
		return -1;
	}

	if (pthread_create(thread, &pattr, start_routine, arg)) {
#ifdef __WINDOWS__
		int winerr = GetLastError();
		pcs_log(LOG_ERR, "pthread_create failed: errno=%d err=%d", errno, winerr);
#else
		pcs_log(LOG_ERR, "pthread_create failed: errno=%d", errno);
#endif
		return -1;
	}

	pthread_attr_destroy(&pattr);
	return 0;
}

int pcs_thread_join(pcs_thread_t thread)
{
	int res = 0;
	res = pthread_join(thread, NULL);
	return -res;
}

pcs_thread_t pcs_thread_self(void)
{
	return pthread_self();
}

int pcs_thread_equal(pcs_thread_t t1, pcs_thread_t t2)
{
	return pthread_equal(t1, t2);
}

void pcs_thread_deadline(struct timespec * ts, unsigned int timeout_ms)
{
#if defined(__LINUX__)
	BUG_ON(clock_gettime(CLOCK_REALTIME, ts));
#else
	abs_time_t t = get_real_time_us();
	ts->tv_sec = t / 1000000;
	ts->tv_nsec = (t % 1000000) * 1000;
#endif

	ts->tv_nsec += (timeout_ms % 1000) * 1000000;
	ts->tv_sec += timeout_ms / 1000;
	while (ts->tv_nsec > 1000000000) {
		ts->tv_nsec -= 1000000000;
		ts->tv_sec++;
	}
}

int pcs_thread_timedjoin(pcs_thread_t thread, void **retval, unsigned int timeout_ms)
{
#if defined(__LINUX__) && __GLIBC_PREREQ(2, 4)
	struct timespec ts;

	pcs_thread_deadline(&ts, timeout_ms);

	return pthread_timedjoin_np(thread, retval, &ts);
#else
	/* TODO: implement timedjoin on other platforms */
	return pthread_join(thread, retval);
#endif
}

int pcs_thread_cond_timedwait(pthread_cond_t * cond, pthread_mutex_t * mutex, unsigned int timeout_ms)
{
	struct timespec ts;

	pcs_thread_deadline(&ts, timeout_ms);

	return pthread_cond_timedwait(cond, mutex, &ts);
}

void pcs_thread_setname(pcs_thread_t thread, const char *name)
{
#if defined(__LINUX__)
  #if __GLIBC_PREREQ(2, 12)
	pthread_setname_np(thread, name);
  #endif
#elif defined(__MAC__)
	pthread_setname_np(name);
#else
	/* no support from platform */
#endif
}

/* ------------------------------------------------------------------------------------------------------- */

#if defined(__WINDOWS__) && !defined(HAVE_TLS_STATIC)

static DWORD tls_idx = TLS_OUT_OF_INDEXES;

void pcs_process_tls_alloc(void)
{
	BUG_ON(tls_idx != TLS_OUT_OF_INDEXES);

	tls_idx = TlsAlloc();
	BUG_ON(tls_idx == TLS_OUT_OF_INDEXES);
}

void pcs_process_tls_free(void)
{
	BUG_ON(tls_idx == TLS_OUT_OF_INDEXES);
	TlsFree(tls_idx);
}

struct __pcs_current * pcs_thread_tls(void)
{
	BUG_ON(tls_idx == TLS_OUT_OF_INDEXES);

	void *tls = TlsGetValue(tls_idx);
	if (tls)
		return tls;

	BUG_ON(GetLastError() != ERROR_SUCCESS);

	tls = pcs_xzmalloc(sizeof(struct __pcs_current));
	BUG_ON(!TlsSetValue(tls_idx, tls));

	return tls;
}

void pcs_thread_tls_free(void)
{
	if (tls_idx == TLS_OUT_OF_INDEXES)
		return;

	void *tls = TlsGetValue(tls_idx);
	TlsSetValue(tls_idx, NULL);

	pcs_free(tls);
}

#else /* __WINDOWS__ */

__thread struct __pcs_current __pcs_thread_tls;

#undef pcs_thread_tls
struct __pcs_current * pcs_thread_tls(void)
{
	return &__pcs_thread_tls;
}

#endif	/* __WINDOWS__ */

void pcs_thread_barrier_init(struct pcs_thread_barrier *barrier, unsigned limit)
{
	pthread_mutex_init(&barrier->mutex, 0);
	pthread_cond_init(&barrier->cond, 0);
	barrier->limit = limit;
	barrier->count = 0;
	barrier->phase = 0;
}

void pcs_thread_barrier_fini(struct pcs_thread_barrier *barrier)
{
	pthread_cond_destroy(&barrier->cond);
	pthread_mutex_destroy(&barrier->mutex);
}

void pcs_thread_barrier_wait(struct pcs_thread_barrier *barrier)
{
	pthread_mutex_lock(&barrier->mutex);
	if (++barrier->count >= barrier->limit) {
		barrier->phase++;
		barrier->count = 0;
		pthread_cond_broadcast(&barrier->cond);
	} else {
		unsigned phase = barrier->phase;
		do {
			pthread_cond_wait(&barrier->cond, &barrier->mutex);
		} while (barrier->phase == phase);
	}
	pthread_mutex_unlock(&barrier->mutex);
}

void pcs_thread_barrier_reset(struct pcs_thread_barrier *barrier, unsigned limit)
{
	pthread_mutex_lock(&barrier->mutex);
	barrier->limit = limit;
	if (barrier->count >= limit) {
		barrier->phase++;
		barrier->count = 0;
		pthread_cond_broadcast(&barrier->cond);
	}
	pthread_mutex_unlock(&barrier->mutex);
}
