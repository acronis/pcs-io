/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "regdump.h"
#include "pcs_compat.h"
#include "pcs_malloc.h"
#include "pcs_ucontext.h"
#include "log.h"
#include <stdlib.h>
#include <stdio.h>

#if !defined(HAVE_LIBUNWIND) && defined(__MAC__)
/* libunwind is part of system library on macOS */
#define HAVE_LIBUNWIND
#endif

#if defined(HAVE_LIBUNWIND) && defined(__LINUX__) && defined(__SANITIZE_ADDRESS__)
/* libunwind on Linux triggers stack-use-after-scope while walking the stack #ABR-156856 */
#undef HAVE_LIBUNWIND
#endif

#ifdef HAVE_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>

static size_t libunwind_backtrace(unw_cursor_t *cursor, void **array, size_t size)
{
	size_t nr = 0;
	do {
		unw_word_t ip;
		unw_get_reg(cursor, UNW_REG_IP, &ip);
		array[nr++] = (void *)ip;
	} while (nr < size && unw_step(cursor) > 0);
	return nr;
}

static void libunwind_init_cursor(unw_cursor_t *cursor, ucontext_t *context)
{
	if (!context) {
		unw_context_t ctx;
		unw_getcontext(&ctx);
		unw_init_local(cursor, &ctx);
	} else {
#if defined(__LINUX__)
		unw_init_local(cursor, (unw_context_t *)context);
#elif defined(__MAC__)
		unw_init_local(cursor, (unw_context_t *)&context->uc_mcontext->__ss);
#else
#error "How to convert ucontext_t into unw_context_t?"
#endif
	}
}
#endif

#ifdef __linux__
#ifdef __x86_64__
/* We will print the register dump in this format:

 RAX: XXXXXXXXXXXXXXXX   RBX: XXXXXXXXXXXXXXXX  RCX: XXXXXXXXXXXXXXXX
 RDX: XXXXXXXXXXXXXXXX   RSI: XXXXXXXXXXXXXXXX  RDI: XXXXXXXXXXXXXXXX
 RBP: XXXXXXXXXXXXXXXX   R8 : XXXXXXXXXXXXXXXX  R9 : XXXXXXXXXXXXXXXX
 R10: XXXXXXXXXXXXXXXX   R11: XXXXXXXXXXXXXXXX  R12: XXXXXXXXXXXXXXXX
 R13: XXXXXXXXXXXXXXXX   R14: XXXXXXXXXXXXXXXX  R15: XXXXXXXXXXXXXXXX
 RSP: XXXXXXXXXXXXXXXX

 RIP: XXXXXXXXXXXXXXXX   EFLAGS: XXXXXXXX

 CS:  XXXX   DS: XXXX   ES: XXXX   FS: XXXX   GS: XXXX

 Trap:  XXXXXXXX   Error: XXXXXXXX   OldMask: XXXXXXXX
 RSP/SIGNAL: XXXXXXXXXXXXXXXX  CR2: XXXXXXXX

 FPUCW: XXXXXXXX   FPUSW: XXXXXXXX   TAG: XXXXXXXX
 IPOFF: XXXXXXXX   CSSEL: XXXX   DATAOFF: XXXXXXXX   DATASEL: XXXX

 ST(0) XXXX XXXXXXXXXXXXXXXX   ST(1) XXXX XXXXXXXXXXXXXXXX
 ST(2) XXXX XXXXXXXXXXXXXXXX   ST(3) XXXX XXXXXXXXXXXXXXXX
 ST(4) XXXX XXXXXXXXXXXXXXXX   ST(5) XXXX XXXXXXXXXXXXXXXX
 ST(6) XXXX XXXXXXXXXXXXXXXX   ST(7) XXXX XXXXXXXXXXXXXXXX

 mxcsr: XXXX
 XMM0 : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XMM1 : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
 XMM2 : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XMM3 : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
 XMM4 : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XMM5 : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
 XMM6 : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XMM7 : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
 XMM8 : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XMM9 : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
 XMM10: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XMM11: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
 XMM12: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XMM13: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
 XMM14: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XMM15: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

 */

#define HAVE_REGISTER_DUMP
void register_dump(ucontext_t *ctx, void (*log_printf)(const char *fmt, ...))
{
	/* Generate the output. */
	log_printf("Register dump:");
	log_printf("");
	log_printf(" RAX: %016llx   RBX: %016llx   RCX: %016llx", ctx->uc_mcontext.gregs[REG_RAX], ctx->uc_mcontext.gregs[REG_RBX], ctx->uc_mcontext.gregs[REG_RCX]);
	log_printf(" RDX: %016llx   RSI: %016llx   RDI: %016llx", ctx->uc_mcontext.gregs[REG_RDX], ctx->uc_mcontext.gregs[REG_RSI], ctx->uc_mcontext.gregs[REG_RDI]);
	log_printf(" RBP: %016llx   R8 : %016llx   R9 : %016llx", ctx->uc_mcontext.gregs[REG_RBP], ctx->uc_mcontext.gregs[REG_R8], ctx->uc_mcontext.gregs[REG_R9]);
	log_printf(" R10: %016llx   R11: %016llx   R12: %016llx", ctx->uc_mcontext.gregs[REG_R10], ctx->uc_mcontext.gregs[REG_R11], ctx->uc_mcontext.gregs[REG_R12]);
	log_printf(" R13: %016llx   R14: %016llx   R15: %016llx", ctx->uc_mcontext.gregs[REG_R13], ctx->uc_mcontext.gregs[REG_R14], ctx->uc_mcontext.gregs[REG_R15]);
	log_printf(" RSP: %016llx", ctx->uc_mcontext.gregs[REG_RSP]);
	log_printf("");
	log_printf(" RIP: %016llx   EFLAGS: %08llx", ctx->uc_mcontext.gregs[REG_RIP], ctx->uc_mcontext.gregs[REG_EFL]);
	log_printf("");
	log_printf(" CS: %04x   FS: %04x   GS: %04x", ctx->uc_mcontext.gregs[REG_CSGSFS] & 0xffff, (ctx->uc_mcontext.gregs[REG_CSGSFS] >> 16) & 0xffff,
		(ctx->uc_mcontext.gregs[REG_CSGSFS] >> 32) & 0xffff);
	log_printf(" Trap: %08llx   Error: %08llx   OldMask: %08llx   CR2: %08llx",
			ctx->uc_mcontext.gregs[REG_TRAPNO], ctx->uc_mcontext.gregs[REG_ERR], ctx->uc_mcontext.gregs[REG_OLDMASK], ctx->uc_mcontext.gregs[REG_CR2]);
	log_printf("");

	if (ctx->uc_mcontext.fpregs != NULL) {
		int i;

		/* Generate output for the FPU control/status registers. */
		log_printf(" FPUCW: %08x   FPUSW: %08x   TAG: %08x",
				ctx->uc_mcontext.fpregs->cwd, ctx->uc_mcontext.fpregs->swd, ctx->uc_mcontext.fpregs->ftw);
		log_printf(" RIP: %08llx   RDP: %08llx", ctx->uc_mcontext.fpregs->rip, ctx->uc_mcontext.fpregs->rdp);
		log_printf("");

		/* Now the real FPU registers. */
		for (i = 0; i < 8; i += 2) {
			log_printf(" ST(%d) %04x %04x%04x%04x%04x    ST(%d) %04x %04x%04x%04x%04x", i,
					ctx->uc_mcontext.fpregs->_st[i].exponent,
					ctx->uc_mcontext.fpregs->_st[i].significand[3],
					ctx->uc_mcontext.fpregs->_st[i].significand[2],
					ctx->uc_mcontext.fpregs->_st[i].significand[1],
					ctx->uc_mcontext.fpregs->_st[i].significand[0],
					i+1,
					ctx->uc_mcontext.fpregs->_st[i+1].exponent,
					ctx->uc_mcontext.fpregs->_st[i+1].significand[3],
					ctx->uc_mcontext.fpregs->_st[i+1].significand[2],
					ctx->uc_mcontext.fpregs->_st[i+1].significand[1],
					ctx->uc_mcontext.fpregs->_st[i+1].significand[0]);
		}
		log_printf("");

		log_printf(" mxcsr: %04x", ctx->uc_mcontext.fpregs->mxcsr);
		for (i = 0; i < 16; i += 2) {
			log_printf(" XMM%-2d: %08x%08x%08x%08x   XMM%-2d: %08x%08x%08x%08x", i,
					ctx->uc_mcontext.fpregs->_xmm[i].element[3],
					ctx->uc_mcontext.fpregs->_xmm[i].element[2],
					ctx->uc_mcontext.fpregs->_xmm[i].element[1],
					ctx->uc_mcontext.fpregs->_xmm[i].element[0],
					i+1,
					ctx->uc_mcontext.fpregs->_xmm[i+1].element[3],
					ctx->uc_mcontext.fpregs->_xmm[i+1].element[2],
					ctx->uc_mcontext.fpregs->_xmm[i+1].element[1],
					ctx->uc_mcontext.fpregs->_xmm[i+1].element[0]);
		}
		log_printf("");
	}

}
#endif	/* __x86_64__ */
#endif	/* __linux__ */

/* --------------------------------------------------------------------------------------------- */

#ifdef _WIN64
void register_dump(ucontext_t *ctx, void (*log_printf)(const char *fmt, ...))
{
	int i;

	/* Generate the output. */
	log_printf("Register dump:");
	log_printf("");
	log_printf(" RAX: %016x   RBX: %016x   RCX: %016x", ctx->ContextRecord->Rax, ctx->ContextRecord->Rbx, ctx->ContextRecord->Rcx);
	log_printf(" RDX: %016x   RSI: %016x   RDI: %016x", ctx->ContextRecord->Rdx, ctx->ContextRecord->Rsi, ctx->ContextRecord->Rdi);
	log_printf(" RBP: %016x   R8 : %016x   R9 : %016x", ctx->ContextRecord->Rbp, ctx->ContextRecord->R8,  ctx->ContextRecord->R9);
	log_printf(" R10: %016x   R11: %016x   R12: %016x", ctx->ContextRecord->R10, ctx->ContextRecord->R11, ctx->ContextRecord->R12);
	log_printf(" R13: %016x   R14: %016x   R15: %016x", ctx->ContextRecord->R13, ctx->ContextRecord->R14, ctx->ContextRecord->R15);
	log_printf(" RSP: %016x", ctx->ContextRecord->Rsp);
	log_printf("");
	log_printf(" RIP: %016x   EFLAGS: %08x", ctx->ContextRecord->Rip, ctx->ContextRecord->EFlags);
	log_printf(" CS: %04x   FS: %04x   GS: %04x", ctx->ContextRecord->SegCs, ctx->ContextRecord->SegFs, ctx->ContextRecord->SegGs);
	log_printf("");
	log_printf(" Addr: %016x   Code: %08x   Flags: %08x",
			ctx->ExceptionRecord->ExceptionAddress, ctx->ExceptionRecord->ExceptionCode, ctx->ExceptionRecord->ExceptionFlags);
	log_printf("");

	/* Generate output for the FPU control/status registers. */
	log_printf(" FPUCW: %04x   FPUSW: %08x   TAG: %08x",
			ctx->ContextRecord->FltSave.ControlWord, ctx->ContextRecord->FltSave.StatusWord, ctx->ContextRecord->FltSave.TagWord);
	log_printf(" RIP: %08x   RDP: %08x", ctx->ContextRecord->FltSave.ErrorOffset, ctx->ContextRecord->FltSave.DataOffset);
	log_printf("");

	/* Now the real FPU registers. */
	for (i = 0; i < 8; i += 2) {
		log_printf(" ST(%d) %08x%08x     ST(%d) %08x%08x", i,
			ctx->ContextRecord->FltSave.FloatRegisters[i].High,
			ctx->ContextRecord->FltSave.FloatRegisters[i].Low,
			i+1,
			ctx->ContextRecord->FltSave.FloatRegisters[i+1].High,
			ctx->ContextRecord->FltSave.FloatRegisters[i+1].Low);
	}
	log_printf("");

	log_printf(" mxcsr: %04x", ctx->ContextRecord->FltSave.MxCsr);
	for (i = 0; i < 16; i += 2) {
		log_printf(" XMM%-2d: %016x%016x   XMM%-2d: %016x%016x", i,
				ctx->ContextRecord->FltSave.XmmRegisters[i].High,
				ctx->ContextRecord->FltSave.XmmRegisters[i].Low,
				i+1,
				ctx->ContextRecord->FltSave.XmmRegisters[i+1].High,
				ctx->ContextRecord->FltSave.XmmRegisters[i+1].Low);
	}
	log_printf("");
}
#elif defined(_WIN32)
void register_dump(ucontext_t *ctx, void (*log_printf)(const char *fmt, ...))
{
	/* Generate the output. */
	log_printf("Register dump:");
	log_printf("");
	log_printf(" EAX: %08x   EBX: %08x   ECX: %08x", ctx->ContextRecord->Eax, ctx->ContextRecord->Ebx, ctx->ContextRecord->Ecx);
	log_printf(" EDX: %08x   ESI: %08x   EDI: %08x", ctx->ContextRecord->Edx, ctx->ContextRecord->Esi, ctx->ContextRecord->Edi);
	log_printf(" EBP: %08x   ESP: %08x", ctx->ContextRecord->Ebp, ctx->ContextRecord->Esp);
	log_printf("");

	log_printf(" EIP: %08x   EFLAGS: %08x", ctx->ContextRecord->Eip, ctx->ContextRecord->EFlags);
	log_printf("");

	log_printf(" CS: %04x   FS: %04x   GS: %04x", ctx->ContextRecord->SegCs, ctx->ContextRecord->SegFs, ctx->ContextRecord->SegGs);
	log_printf("");

	log_printf(" Addr: %08x   Code: %08x   Flags: %08x", ctx->ExceptionRecord->ExceptionAddress, ctx->ExceptionRecord->ExceptionCode, ctx->ExceptionRecord->ExceptionFlags);
	log_printf("");
}
#endif /* _WIN32 */

#ifdef __WINDOWS__
#include <dbghelp.h>

typedef PVOID(__stdcall *tSymFunctionTableAccess64)(HANDLE hProcess, DWORD64 AddrBase);
typedef DWORD64(__stdcall *tSymGetModuleBase64)(IN HANDLE hProcess, IN DWORD64 dwAddr);
typedef BOOL(__stdcall *tSymGetModuleInfo64)(IN HANDLE hProcess, IN DWORD64 dwAddr, OUT PIMAGEHLP_MODULE64 ModuleInfo);
typedef DWORD(__stdcall *tSymGetOptions)(VOID);
typedef BOOL(__stdcall *tSymGetSymFromAddr64)(IN HANDLE hProcess, IN DWORD64 dwAddr,
	OUT PDWORD64 pdwDisplacement, OUT PIMAGEHLP_SYMBOL64 Symbol);
typedef BOOL(__stdcall *tSymInitialize)(IN HANDLE hProcess, IN PSTR UserSearchPath, IN BOOL fInvadeProcess);
typedef DWORD(__stdcall *tSymLoadModule64)(IN HANDLE hProcess, IN HANDLE hFile,
	IN PSTR ImageName, IN PSTR ModuleName, IN DWORD64 BaseOfDll, IN DWORD SizeOfDll);
typedef DWORD(__stdcall *tSymSetOptions)(IN DWORD SymOptions);
typedef BOOL(__stdcall *tStackWalk64)(
	DWORD MachineType,
	HANDLE hProcess,
	HANDLE hThread,
	LPSTACKFRAME64 StackFrame,
	PVOID ContextRecord,
	PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine,
	PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
	PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
	PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress);
typedef DWORD(__stdcall WINAPI *tUnDecorateSymbolName)(PCSTR DecoratedName, PSTR UnDecoratedName,
	DWORD UndecoratedLength, DWORD Flags);

#define SYM_FUNCS(OP)			\
	OP(StackWalk64)			\
	OP(SymFunctionTableAccess64)	\
	OP(SymGetModuleBase64)		\
	OP(SymGetModuleInfo64)		\
	OP(SymGetOptions)		\
	OP(SymGetSymFromAddr64)		\
	OP(SymInitialize)		\
	OP(SymSetOptions)		\
	OP(UnDecorateSymbolName)

#define DECLARE_STATIC(func) static t ## func p ## func = NULL;
SYM_FUNCS(DECLARE_STATIC)
#undef DECLARE_STATIC

static HANDLE g_dbghelp = INVALID_HANDLE_VALUE;
#ifdef _WIN64
#define IMAGE_TYPE IMAGE_FILE_MACHINE_AMD64
#define RegIP(CTX) (CTX).Rip
#define RegSP(CTX) (CTX).Rsp
#define RegFP(CTX) (CTX).Rdi
#else
#define IMAGE_TYPE IMAGE_FILE_MACHINE_I386
#define RegIP(CTX) (CTX).Eip
#define RegSP(CTX) (CTX).Esp
#define RegFP(CTX) (CTX).Ebp
#endif

#define SEARCH_PATH_MAX 2048

/* If len is non-zero and less than path_sz, add value separator ';' and set *ptr to next character.
 * len does not include terminating null character. */
static void advance_ptr(char **pptr, DWORD len, size_t path_sz)
{
	if (!len || len >= path_sz)
		return;

	char *ptr = *pptr;
	ptr += len;
	*ptr = ';';
	ptr++;
	*ptr = 0;
	*pptr = ptr;
}

static char * create_search_path(size_t path_sz)
{
	char *search_path = pcs_malloc(path_sz);
	if (!search_path)
		return NULL;

	DWORD len;
	char *end = search_path + path_sz;
	char *ptr = search_path;

	*ptr = 0;

	len = GetCurrentDirectoryA((DWORD)(end - ptr), ptr);
	advance_ptr(&ptr, len, end - ptr);

	len = GetModuleFileNameA(0, ptr, (DWORD)(end - ptr));
	if (len && len < end - ptr) {
		/* Find rightmost path separator */
		char *p;
		for (p = ptr + len - 1; p > ptr; p--) {
			if (*p == '\\' || *p == '/' || *p == ':') {
				/* Separator found, add directory to search path */
				if (*p == ':') /* leave colon */
					p++;

				*p = ';';
				ptr = p + 1;
				*ptr = 0;
				break;
			}
		}
	}

	len = GetEnvironmentVariableA("_NT_SYMBOL_PATH", ptr, (DWORD)(end - ptr));
	advance_ptr(&ptr, len, end - ptr);
	len = GetEnvironmentVariableA("_NT_ALTERNATE_SYMBOL_PATH", ptr, (DWORD)(end - ptr));
	advance_ptr(&ptr, len, end - ptr);
	len = GetEnvironmentVariableA("SYSTEMROOT", ptr, (DWORD)(end - ptr));
	advance_ptr(&ptr, len, end - ptr);

	if (ptr - 1 > search_path) {
		/* If we added anything, the last character is ';' */
		ptr[-1] = 0;
	}

	return search_path;
}

static int sym_init(void (*log_printf)(const char *fmt, ...))
{
	static int initialized = 0;
	if (initialized)
		return g_dbghelp == NULL ? -1 : 0;

	char *search_path = NULL;

	initialized = 1;

	g_dbghelp = LoadLibrary(TEXT("dbghelp.dll"));
	if (g_dbghelp == NULL)
		return -1;

#define GET_ADDRESS(func) \
	p ## func = (t ## func) GetProcAddress(g_dbghelp, #func);	\
	if (!(p ## func)) {						\
		log_printf("sym_init: unable to find %s", #func);	\
		goto fail;						\
	}								\

	SYM_FUNCS(GET_ADDRESS)
#undef GET_ADDRESS

	search_path = create_search_path(SEARCH_PATH_MAX);

	if (!pSymInitialize(GetCurrentProcess(), search_path, TRUE)) {
		log_printf("sym_init: SymInitialize failed: %d", GetLastError());
		goto fail;
	}

	DWORD symOptions;
	symOptions = pSymGetOptions();
	symOptions |= SYMOPT_LOAD_LINES;
	symOptions &= ~SYMOPT_UNDNAME;
	symOptions &= ~SYMOPT_DEFERRED_LOADS;
	pSymSetOptions(symOptions);

	pcs_free(search_path);
	return 0;

fail:
	pcs_free(search_path);
	FreeLibrary(g_dbghelp);
	g_dbghelp = NULL;
	return -1;
}

static void addr2name(HANDLE proc, DWORD64 addr, char *name, int len)
{
	static BYTE symBuffer[sizeof(IMAGEHLP_SYMBOL64) + MAX_SYM_NAME];
	static char undName[MAX_SYM_NAME];
	static IMAGEHLP_SYMBOL64 *pSym = (IMAGEHLP_SYMBOL64*)symBuffer;
	pSym->SizeOfStruct = sizeof(*pSym);
	pSym->MaxNameLength = MAX_SYM_NAME;

	DWORD64 offs;
	if (pSymGetSymFromAddr64(proc, addr, &offs, pSym)) {
		char *sym = pUnDecorateSymbolName(pSym->Name, undName, sizeof(undName), UNDNAME_COMPLETE)
			? pSym->Name
			: undName;
		snprintf(name, len, "%s+0x%llx", sym, offs);
	}
	else {
		name[0] = 0;
	}
}

static void trace_dump_ctx(CONTEXT *ctx, void (*log_printf)(const char *fmt, ...))
{
	if (sym_init(log_printf)) {
		log_printf("sym_init() failed");
		return;
	}

	STACKFRAME64 stackframe;
	memset(&stackframe, 0, sizeof stackframe);
	stackframe.AddrPC.Offset = RegIP(*ctx);
	stackframe.AddrPC.Mode = AddrModeFlat;
	stackframe.AddrFrame.Offset = RegFP(*ctx);
	stackframe.AddrFrame.Mode = AddrModeFlat;
	stackframe.AddrStack.Offset = RegSP(*ctx);
	stackframe.AddrStack.Mode = AddrModeFlat;

	HANDLE proc = GetCurrentProcess();
	HANDLE thr = GetCurrentThread();

	int frame_nr;
	for (frame_nr = 0; ; frame_nr++) {
		if (!pStackWalk64(IMAGE_TYPE, proc, thr, &stackframe, ctx, NULL, pSymFunctionTableAccess64, pSymGetModuleBase64, NULL))
			break;

		DWORD64 addr = stackframe.AddrPC.Offset;

		static IMAGEHLP_MODULE64 module;
		module.SizeOfStruct = sizeof(module);
		if (!pSymGetModuleInfo64(proc, addr, &module))
			module.ModuleName[0] = 0;

		static char name[MAX_SYM_NAME];
		addr2name(proc, addr, name, sizeof(name));
		log_printf("%2d: %s(%s) [0x%llx]", frame_nr, module.ModuleName, name, addr);

		if (stackframe.AddrReturn.Offset == 0) {
			SetLastError(0);
			break;
		}
	}

	int err = GetLastError();
	if (err)
		log_printf("StackWalk64 failed with error %d", err);
	log_printf("");
}

void trace_dump(ucontext_t *uctx, void (*log_printf)(const char *fmt, ...))
{
	CONTEXT ctx;

	if (uctx) {
		ctx = *uctx->ContextRecord;
	} else {
#ifdef _WIN64
		RtlCaptureContext(&ctx);
#else
		memset(&ctx, 0, sizeof(ctx));
		__asm {
current_eip:		mov [ctx.Ebp], ebp
			mov [ctx.Esp], esp
			mov eax, [current_eip]
			mov [ctx.Eip], eax
		}
#endif
	}

	trace_dump_ctx(&ctx, log_printf);
}
#else /* !__WINDOWS__ */
#if defined(__LINUX__) || defined(__MAC__)
static void symbols_dump(void **array, size_t size, void (*log_printf)(const char *fmt, ...))
{
	char **strings = backtrace_symbols(array, size);

	log_printf("---------- [%zd stack frames] ----------", size);

	size_t i;
	for (i = 0; i < size; i++)
		log_printf("%s", strings[i]);

	pcs_native_free(strings);
	log_printf("");
}
#endif /* __LINUX__ || __MAC__ */

void trace_dump(ucontext_t *context, void (*log_printf)(const char *fmt, ...))
{
#if defined(__LINUX__) || defined(__MAC__)
	void *array[128];
#ifdef HAVE_LIBUNWIND
	unw_cursor_t cursor;
	libunwind_init_cursor(&cursor, context);
	size_t size = libunwind_backtrace(&cursor, array, sizeof(array) / sizeof(array[0]));
#else
	size_t size = backtrace(array, sizeof(array) / sizeof(array[0]));
#endif
	symbols_dump(array, size, log_printf);
#endif /* __LINUX__ || __MAC__ */
}

#ifndef HAVE_REGISTER_DUMP
void register_dump(ucontext_t *ctx, void (*log_printf)(const char *fmt, ...))
{
}
#endif
#endif /* !__WINDOWS__ */

void trace_dump_coroutine(struct pcs_ucontext *context, void (*log_printf)(const char *fmt, ...))
{
#if defined(HAVE_LIBUNWIND) && (defined(__LINUX__) || defined(__MAC__)) && defined(__x86_64__)
	unw_context_t ctx;
	unw_getcontext(&ctx);
	unw_cursor_t cursor;
	unw_init_local(&cursor, &ctx);

	/* order should match to pcs_ucontext.c */
	void **sp = context->sp;
	unw_set_reg(&cursor, UNW_X86_64_RBX, (unw_word_t)*(sp++));
	unw_set_reg(&cursor, UNW_X86_64_R12, (unw_word_t)*(sp++));
	unw_set_reg(&cursor, UNW_X86_64_R13, (unw_word_t)*(sp++));
	unw_set_reg(&cursor, UNW_X86_64_R14, (unw_word_t)*(sp++));
	unw_set_reg(&cursor, UNW_X86_64_R15, (unw_word_t)*(sp++));
	unw_set_reg(&cursor, UNW_X86_64_RBP, (unw_word_t)*(sp++));
	unw_set_reg(&cursor, UNW_REG_IP, (unw_word_t)*(sp++));
	unw_set_reg(&cursor, UNW_REG_SP, (unw_word_t)sp);

	void *array[128];
	size_t size = libunwind_backtrace(&cursor, array, sizeof(array) / sizeof(array[0]));
	symbols_dump(array, size, log_printf);
#elif defined(HAVE_LIBUNWIND) && defined(__LINUX__) && defined(__i386__)
	unw_context_t ctx;
	unw_getcontext(&ctx);
	unw_cursor_t cursor;
	unw_init_local(&cursor, &ctx);

	/* order should match to pcs_ucontext.c */
	void **sp = context->sp;
	unw_set_reg(&cursor, UNW_X86_EBX, (unw_word_t)*(sp++));
	unw_set_reg(&cursor, UNW_X86_ESI, (unw_word_t)*(sp++));
	unw_set_reg(&cursor, UNW_X86_EDI, (unw_word_t)*(sp++));
	unw_set_reg(&cursor, UNW_X86_EBP, (unw_word_t)*(sp++));
	unw_set_reg(&cursor, UNW_REG_IP, (unw_word_t)*(sp++));
	unw_set_reg(&cursor, UNW_REG_SP, (unw_word_t)sp);

	void *array[128];
	size_t size = libunwind_backtrace(&cursor, array, sizeof(array) / sizeof(array[0]));
	symbols_dump(array, size, log_printf);
#elif defined(__WINDOWS__)
#ifdef _WIN64
	CONTEXT ctx = *(CONTEXT *)((u8 *)context->fiber + 0x30);
	ctx.Rsp += 8;
#else
	CONTEXT ctx = *(CONTEXT *)((u8 *)context->fiber + 0x14);
	ctx.Eip = *(DWORD*)ctx.Esp;
	ctx.Esp += 8;
#endif
	trace_dump_ctx(&ctx, log_printf);
#endif
}
