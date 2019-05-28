/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#pragma once

#include "pcs_types.h"

#if defined(__WINDOWS__)

struct pcs_ucontext {
	void	*fiber;
};

void pcs_ucontext_switch(struct pcs_ucontext *save, struct pcs_ucontext *load);

#define PCS_UCONTEXT_FUNC	CALLBACK
#define PCS_UCONTEXT_TOPMOST

#else /* __WINDOWS__ */

#if (defined(__LINUX__) || defined(__MAC__) || defined(__SUN__)) && (defined(__i386__) || defined(__x86_64__) || defined(__aarch64__))

struct pcs_ucontext {
	void	*sp;
};

void pcs_ucontext_switch(struct pcs_ucontext *save, struct pcs_ucontext *load);

#ifdef __x86_64__
#define PCS_UCONTEXT_TOPMOST	__asm__ __volatile__(".cfi_undefined rip")
#elif defined(__i386__)
#define PCS_UCONTEXT_TOPMOST	__asm__ __volatile__(".cfi_undefined eip")
#elif defined(__aarch64__)
#define PCS_UCONTEXT_TOPMOST	__asm__ __volatile__(".cfi_undefined x30")
#endif

#else

#include <setjmp.h>

struct pcs_ucontext {
	sigjmp_buf	jmpbuf;
};

static inline void pcs_ucontext_switch(struct pcs_ucontext *save, struct pcs_ucontext *load)
{
	if (!sigsetjmp(save->jmpbuf, 0))
		siglongjmp(load->jmpbuf, 1);
}

#define PCS_UCONTEXT_TOPMOST

#endif

void pcs_ucontext_init(struct pcs_ucontext *context, void *stack, u32 stack_sz, void (*func)(void*), void *arg);

#define PCS_UCONTEXT_FUNC

#endif /* __WINDOWS__ */
