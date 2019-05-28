/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_atexit.h"
#include "pcs_malloc.h"
#include "bug.h"

#include <stdlib.h>
#include <pthread.h>

/* The hooks chain head pointer */
static struct pcs_atexit_hook* pcs_atexit_hooks = NULL;
static pthread_mutex_t pcs_atexit_lock = PTHREAD_MUTEX_INITIALIZER;

static void pcs_atexit_(void)
{
	pcs_call_atexit(exit_normal);
}

/* Register hook to called on exit */
PCS_API void pcs_atexit(struct pcs_atexit_hook* hook)
{
	int first_hook;
	BUG_ON(!hook->cb);

	pthread_mutex_lock(&pcs_atexit_lock);
	first_hook = !pcs_atexit_hooks;
	hook->exit_type = exit_none;
	hook->next = pcs_atexit_hooks;
	pcs_atexit_hooks = hook;
	pthread_mutex_unlock(&pcs_atexit_lock);

	if (first_hook) {
		atexit(pcs_atexit_);
	}
}

/* Un-register hook */
PCS_API void pcs_atexit_unreg(struct pcs_atexit_hook const* hook)
{
	struct pcs_atexit_hook* curr;
	struct pcs_atexit_hook** link = &pcs_atexit_hooks;

	pthread_mutex_lock(&pcs_atexit_lock);
	while ((curr = *link)) {
		if (curr == hook) {
			*link = curr->next;
			break;
		}
		link = &curr->next;
	}
	pthread_mutex_unlock(&pcs_atexit_lock);

	if (curr) {
		pcs_free(curr);
	}
}

/* Call atexit hooks (used internally) */
void pcs_call_atexit(exit_type_t exit_type)
{
	struct pcs_atexit_hook *head, *hook;

	pthread_mutex_lock(&pcs_atexit_lock);
	head = pcs_atexit_hooks;
	pcs_atexit_hooks = NULL;
	pthread_mutex_unlock(&pcs_atexit_lock);

	while ((hook = head)) {
		head = hook->next;
		hook->exit_type = exit_type;
		hook->cb(hook);
	}
}
