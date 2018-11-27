/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_SIGNAL_H
#define _PCS_SIGNAL_H

#include <signal.h>
#include "pcs_types.h"
#include "pcs_process.h"

typedef void (*pcs_sighandler_t)(struct pcs_process *proc, int signal, void *priv);

PCS_API void pcs_signal_block(sigset_t *mask);
PCS_API int pcs_signal_add_handler(struct pcs_process *proc, sigset_t *mask, pcs_sighandler_t handler, void *priv);
PCS_API int pcs_signal_set_defaults(struct pcs_process *proc);
PCS_API int pcs_signal_set_fatal_handlers(void);

/* For internal use */
void pcs_signal_fini(struct pcs_process *proc);
void pcs_signal_call_handler(struct pcs_ioconn *conn, int signal);

#endif /* _PCS_SIGNAL_H */
