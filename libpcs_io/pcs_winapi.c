/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_winapi.h"

#ifdef __WINDOWS__
#include "log.h"
#include "pcs_thread.h"
#include "pcs_sock.h"

PNtQueryInformationFile NtQueryInformationFilePtr;
PNtQueryVolumeInformationFile NtQueryVolumeInformationFilePtr;
PRtlNtStatusToDosError RtlNtStatusToDosErrorPtr;
PNtQueryDirectoryFile NtQueryDirectoryFilePtr;

PGetQueuedCompletionStatusEx GetQueuedCompletionStatusExPtr;
PCancelIoEx CancelIoExPtr;
PSetFileCompletionNotificationModes SetFileCompletionNotificationModesPtr;

PGetSystemTimePreciseAsFileTime GetSystemTimePreciseAsFileTimePtr;
PQueryUnbiasedInterruptTime QueryUnbiasedInterruptTimePtr;

int pcs_winapi_init(void)
{
	static int rc = 1;
	if (rc <= 0)
		return rc;

	HMODULE ntdll_module = GetModuleHandleW(L"ntdll.dll");
	BUG_ON(!ntdll_module);

#define LOAD(module, sym) do {								\
		sym ## Ptr = (P ## sym)GetProcAddress(module, #sym);			\
		if (sym ## Ptr == NULL) {						\
			rc = -(int)GetLastError();					\
			pcs_log(LOG_ERR, "failed to get proc address of %s", #sym);	\
			return rc;							\
		}									\
	} while (0)

#define LOAD_OPTIONAL(module, sym) do {							\
		sym ## Ptr = (P ## sym)GetProcAddress(module, #sym);			\
	} while (0)

	LOAD(ntdll_module, RtlNtStatusToDosError);
	LOAD(ntdll_module, NtQueryInformationFile);
	LOAD(ntdll_module, NtQueryVolumeInformationFile);
	LOAD(ntdll_module, NtQueryDirectoryFile);

	HMODULE kern_module = GetModuleHandleW(L"kernel32.dll");
	BUG_ON(!kern_module);

	LOAD_OPTIONAL(kern_module, GetQueuedCompletionStatusEx);
	LOAD_OPTIONAL(kern_module, SetFileCompletionNotificationModes);
	LOAD_OPTIONAL(kern_module, CancelIoEx);

	LOAD_OPTIONAL(kern_module, GetSystemTimePreciseAsFileTime);
	LOAD_OPTIONAL(kern_module, QueryUnbiasedInterruptTime);

	rc = 0;
	return rc;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH: {
		int rc = pcs_winapi_init();
		BUG_ON(rc);
#ifndef HAVE_TLS_STATIC
		pcs_process_tls_alloc();
#endif
		break;
	}
	case DLL_PROCESS_DETACH:
#ifndef HAVE_TLS_STATIC
		pcs_process_tls_free();
#endif
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
#ifndef HAVE_TLS_STATIC
		pcs_thread_tls_free();
#endif
		break;
	}
	return TRUE;
}

#else
int _pcs_winapi_make_ranlib_has_no_symbols_happy = 1;
#endif /* __WINDOWS__ */
