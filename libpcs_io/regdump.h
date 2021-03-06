/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _REGISTER_DUMP
#define _REGISTER_DUMP

#include "pcs_types.h"

#if defined(__LINUX__) || defined(__MAC__) || defined(__SUN__)
#include <execinfo.h> /* for backtraces */
#include <signal.h>
#include <stddef.h>
#elif defined(_WIN32)
typedef EXCEPTION_POINTERS ucontext_t;
#else
typedef void ucontext_t;
#endif

struct pcs_ucontext;

static inline void *register_get_pc(ucontext_t *context)
{
#if defined(__LINUX__) && defined(__x86_64__)
	return (void *)context->uc_mcontext.gregs[REG_RIP];
#elif defined(__LINUX__) && defined(__i386__)
	return (void *)context->uc_mcontext.gregs[REG_EIP];
#elif defined(__MAC__) && defined(__x86_64__)
	return (void *)context->uc_mcontext->__ss.__rip;
#elif defined(__aarch64__)
	return (void *)context->uc_mcontext.pc;
#else
	return NULL;
#endif
}

static inline void register_set_bp(ucontext_t *context, ULONG_PTR bp)
{
#if defined(__LINUX__) && defined(__x86_64__)
	context->uc_mcontext.gregs[REG_RBP] = bp;
#elif defined(__LINUX__) && defined(__i386__)
	context->uc_mcontext.gregs[REG_EBP] = bp;
#elif defined(__MAC__) && defined(__x86_64__)
	context->uc_mcontext->__ss.__rbp = bp;
#elif defined(__aarch64__)
	/* X29 - frame pointer */
	context->uc_mcontext.regs[29] = bp;
#endif
}

typedef void (*log_printf_fn)(void *arg, const char *fmt, ...) __printf(2, 3);
void register_dump(ucontext_t *ctx, log_printf_fn log_printf, void *arg);
void trace_dump(ucontext_t *ctx, log_printf_fn log_printf, void *arg);
void trace_dump_coroutine(struct pcs_ucontext *ctx, log_printf_fn log_printf, void *arg);

#endif /* _REGISTER_DUMP */
