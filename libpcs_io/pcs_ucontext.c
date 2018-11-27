/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_ucontext.h"
#include "bug.h"

void pcs_ucontext_trampoline(void);

#if (defined(__LINUX__) || defined(__MAC__) || defined(__SUN__)) && defined(__x86_64__)

#ifdef __MAC__
#define UNDERSCORE "_"
#else
#define UNDERSCORE ""
#endif

__asm__(".global " UNDERSCORE "pcs_ucontext_switch\n"
	UNDERSCORE "pcs_ucontext_switch:\n\t"
	"pushq %rbp\n\t"
	"pushq %r15\n\t"
	"pushq %r14\n\t"
	"pushq %r13\n\t"
	"pushq %r12\n\t"
	"pushq %rbx\n\t"
	"movq %rsp, (%rdi)\n\t"
	"movq (%rsi), %rsp\n\t"
	"popq %rbx\n\t"
	"popq %r12\n\t"
	"popq %r13\n\t"
	"popq %r14\n\t"
	"popq %r15\n\t"
	"popq %rbp\n\t"
	"retq");

__asm__(".global " UNDERSCORE "pcs_ucontext_trampoline\n"
	UNDERSCORE "pcs_ucontext_trampoline:\n\t"
	".cfi_startproc\n\t"
	".cfi_undefined rip\n\t"
	"movq %r12, %rdi\n\t"
	"jmpq *%rbx\n\t"
	".cfi_endproc");

void pcs_ucontext_init(struct pcs_ucontext *context, void *stack, u32 stack_sz, void (*func)(void*), void *arg)
{
	void **sp = stack + stack_sz;
	BUG_ON((ULONG_PTR)sp & 0xF);

	*(--sp) = 0;
	*(--sp) = pcs_ucontext_trampoline;
	*(--sp) = 0;	/* rbp */
	*(--sp) = 0;	/* r15 */
	*(--sp) = 0;	/* r14 */
	*(--sp) = 0;	/* r13 */
	*(--sp) = arg;	/* r12 */
	*(--sp) = func;	/* rbx */
	context->sp = sp;
}

#elif defined(__LINUX__) && defined(__i386__)

__asm__(".global pcs_ucontext_switch\n"
	"pcs_ucontext_switch:\n\t"
	"pushl %ebp\n\t"
	"pushl %edi\n\t"
	"pushl %esi\n\t"
	"pushl %ebx\n\t"
	"movl 20(%esp), %eax\n\t"
	"movl %esp, (%eax)\n\t"
	"movl 24(%esp), %eax\n\t"
	"movl (%eax), %esp\n\t"
	"popl %ebx\n\t"
	"popl %esi\n\t"
	"popl %edi\n\t"
	"popl %ebp\n\t"
	"retl");

__asm__(".global pcs_ucontext_trampoline\n"
	"pcs_ucontext_trampoline:\n\t"
	".cfi_startproc\n\t"
	".cfi_undefined eip\n\t"
	"jmpl *%ebx\n\t"
	".cfi_endproc");

void pcs_ucontext_init(struct pcs_ucontext *context, void *stack, u32 stack_sz, void (*func)(void*), void *arg)
{
	void **sp = stack + stack_sz;
	BUG_ON((ULONG_PTR)sp & 0xF);

	*(--sp) = 0;
	*(--sp) = 0;
	*(--sp) = 0;
	*(--sp) = arg;
	*(--sp) = 0;
	*(--sp) = (void *)pcs_ucontext_trampoline;
	*(--sp) = 0;		/* ebp */
	*(--sp) = 0;		/* edi */
	*(--sp) = 0;		/* esi */
	*(--sp) = (void *)func;	/* ebx */
	context->sp = sp;
}

#elif defined(__WINDOWS__)

void pcs_ucontext_switch(struct pcs_ucontext *save, struct pcs_ucontext *load)
{
	BUG_ON(save->fiber != GetCurrentFiber());
	SwitchToFiber(load->fiber);
}

#else

#include "pcs_config.h"
#include "regdump.h"
#include "bug.h"

#include <ucontext.h>

#ifdef PCS_ADDRESS_SANITIZER
#include <sanitizer/lsan_interface.h>
#endif

/* -------------------------------------------------------------------------------------------------------------------------- */
#ifdef __MAC__
/* Mac OS X crap: if _XOPEN_SOURCE is defined too late, then ucontext_t will be defined w/o last field (__mcontext_data):
 *
 * _STRUCT_UCONTEXT
 * {
 *	...
 *	_STRUCT_MCONTEXT	*uc_mcontext;
 *  #ifdef _XOPEN_SOURCE
 *	_STRUCT_MCONTEXT	__mcontext_data;
 *  #endif
 * };
 *
 * yet uc_mcontext pointer will refer to it and getcontext/swapcontext will simply modify the memory at the end of our structure
 * which is not there - just because our declaration is missing this last @#$@#$ field... Safety check: make sure this field exists
 */
BUILD_BUG_ON(!__builtin_offsetof(ucontext_t, __mcontext_data));
#endif
/* -------------------------------------------------------------------------------------------------------------------------- */

/* Workaround for stupidity of makecontext() API, which takes set of integer args. */
union _helper_arg
{
	void	*data_p;
	int	data32[2];
};

struct _context_arg
{
	struct pcs_ucontext *context;
	void (*func)(void*);
	void *arg;
	struct pcs_ucontext ret_context;
};

static void _context_start(int arg0, int arg1)
{
	union _helper_arg helper_arg = {.data32 = {arg0, arg1}};
	struct _context_arg *context_arg = helper_arg.data_p;
	void (*func)(void*) = context_arg->func;
	void *arg = context_arg->arg;

#ifdef PCS_ADDRESS_SANITIZER
	const void *stack_bottom;
	size_t stack_size;
	__sanitizer_finish_switch_fiber(NULL, &stack_bottom, &stack_size);

	void *fake_stack;
	__sanitizer_start_switch_fiber(&fake_stack, stack_bottom, stack_size);
#endif
	pcs_ucontext_switch(context_arg->context, &context_arg->ret_context);
	func(arg);
}

void pcs_ucontext_init(struct pcs_ucontext *context, void *stack, u32 stack_sz, void (*func)(void*), void *arg)
{
	struct _context_arg context_arg = {.context = context, .func = func, .arg = arg};
	union _helper_arg helper_arg = {.data_p = &context_arg};
	ucontext_t uc1, uc2;

	if (getcontext(&uc1))
		BUG();

	uc1.uc_link = NULL;
	uc1.uc_stack.ss_sp = stack;
	uc1.uc_stack.ss_size = stack_sz;
	uc1.uc_stack.ss_flags = 0;

	/* makecontext() is broken, at least in glibc. It does not initialize BP
	 * and creates broken frame with random bp saved from getcontext() above.
	 * If the address of current thread stack is less than one of new stack
	 * (it is puzzle, but it is almost always true!), everything is OK.
	 * If it is not, backtrace() is confused. If gcc uses RBP as a free register
	 * (it is with -fomit-frame-pointer), backtrace can even segfault.
	 * So, we have to initialize it with bare hands.
	 *
	 * XXX what about threads? Should check just to avoid surprizes.
	 */
	register_set_bp(&uc1, 0);

	/* prepare context for _coroutine_start */
	makecontext(&uc1, (void (*)(void))_context_start, 2, helper_arg.data32[0], helper_arg.data32[1]);

#ifdef PCS_ADDRESS_SANITIZER
	void *fake_stack;
	__sanitizer_start_switch_fiber(&fake_stack, stack + stack_sz, stack_sz);
#endif
	if (!sigsetjmp(context_arg.ret_context.jmpbuf, 0)) {
		swapcontext(&uc2, &uc1);
		BUG();
	}
#ifdef PCS_ADDRESS_SANITIZER
	__sanitizer_finish_switch_fiber(fake_stack, NULL, NULL);
#endif
}

#endif
