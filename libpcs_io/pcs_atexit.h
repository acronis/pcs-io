/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_ATEXIT_H_INCLUDED
#define _PCS_ATEXIT_H_INCLUDED

#include "pcs_types.h"

typedef enum {
	exit_none   = 0,  /* the place-holder for not yet fired hook */
	exit_normal = 1,  /* normal termination */
	exit_abort  = 2,  /* pcs_abort called */
	exit_fatal  = 4,  /* fatal signal received */
} exit_type_t;

struct pcs_atexit_hook {
	void                  (*cb)(struct pcs_atexit_hook const*);
	void*                   priv;
	exit_type_t             exit_type;
	struct pcs_atexit_hook* next;
};

/* Register hook to called on exit */
PCS_API void pcs_atexit(struct pcs_atexit_hook* hook);

/* Un-register hook */
PCS_API void pcs_atexit_unreg(struct pcs_atexit_hook const* hook);

/* Call atexit hooks (used internally) */
void pcs_call_atexit(exit_type_t exit_type);

#endif

