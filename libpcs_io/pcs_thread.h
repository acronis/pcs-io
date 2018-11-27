/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCS_THREAD_H__
#define __PCS_THREAD_H__

#include "pcs_types.h"

#include <pthread.h>
#define pcs_thread_t pthread_t
#define pcs_thread_ret_t void*

typedef struct pcs_thread_attr {
	unsigned long stack_size;
} pcs_thread_attr_t;

int pcs_thread_create(pcs_thread_t * thread, const pcs_thread_attr_t * attr, pcs_thread_ret_t (*start_routine)(void *), void * arg);
int pcs_thread_join(pcs_thread_t thread);
pcs_thread_t pcs_thread_self(void);
int pcs_thread_equal(pcs_thread_t t1, pcs_thread_t t2);

int pcs_thread_timedjoin(pcs_thread_t thread, void **retval, unsigned int timeout_ms);
int pcs_thread_cond_timedwait(pthread_cond_t * cond, pthread_mutex_t * mutex, unsigned int timeout_ms);
void pcs_thread_deadline(struct timespec * ts, unsigned int timeout_ms);
PCS_API void pcs_thread_setname(const char *name);
unsigned long pcs_thread_id(void);

struct pcs_thread_barrier {
	pthread_mutex_t mutex;
	pthread_cond_t  cond;
	unsigned	limit;
	unsigned	count;
	unsigned	phase;
};

PCS_API void pcs_thread_barrier_init(struct pcs_thread_barrier *barrier, unsigned limit);
PCS_API void pcs_thread_barrier_fini(struct pcs_thread_barrier *barrier);
PCS_API void pcs_thread_barrier_wait(struct pcs_thread_barrier *barrier);
PCS_API void pcs_thread_barrier_reset(struct pcs_thread_barrier *barrier, unsigned limit);

/* ------------------------------------------------------------------------------------------------ */
/*
 * TLS compatibility with Windows delay load, where __thread variables do not work properly.
 * Ideally this code should be killed when delay load is removed and all context variables
 * should be simply defined as __thread in places they are needed.
 */

#include "pcs_config.h"

struct pcs_evloop;
struct pcs_coroutine;

struct __pcs_current {
	struct pcs_process *proc;
	struct pcs_evloop *evloop;
	struct pcs_coroutine *co;
};

PCS_API struct __pcs_current * pcs_thread_tls(void);
#ifdef HAVE_TLS_STATIC
PCS_API extern __thread struct __pcs_current __pcs_thread_tls;
#define pcs_thread_tls() (&__pcs_thread_tls)
#else
void pcs_thread_tls_free(void);
void pcs_process_tls_alloc(void);
void pcs_process_tls_free(void);
#endif

/* ------------------------------------------------------------------------------------------------ */

#endif	/* __PCS_THREAD_H__ */
