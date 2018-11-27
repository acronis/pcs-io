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
PSetThreadDescription SetThreadDescriptionPtr;

Ptc_malloc tc_mallocPtr;
Ptc_realloc tc_reallocPtr;
Ptc_free tc_freePtr;

// Copy-paste from VersionHelpers.h Win8.1 SDK
//   (GetVersion* functions are deprecated starting with Win8.1 - see https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getversion)
FORCEINLINE BOOL IsWindowsVersionOrGreater(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor)
{
	OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, { 0 }, 0, 0 };
	DWORDLONG        const dwlConditionMask = VerSetConditionMask(
		VerSetConditionMask(
		VerSetConditionMask(
		0, VER_MAJORVERSION, VER_GREATER_EQUAL),
		VER_MINORVERSION, VER_GREATER_EQUAL),
		VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);

	osvi.dwMajorVersion = wMajorVersion;
	osvi.dwMinorVersion = wMinorVersion;
	osvi.wServicePackMajor = wServicePackMajor;

	return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask) != FALSE;
}

FORCEINLINE BOOL IsWindowsVistaOrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_VISTA), LOBYTE(_WIN32_WINNT_VISTA), 0);
}

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
	LOAD_OPTIONAL(kern_module, SetThreadDescription);

	tc_mallocPtr = &malloc;
	tc_reallocPtr = &realloc;
	tc_freePtr = &free;

#ifdef _USE_TCMALLOC
	// tcmalloc library uses static TLS that is not supported along with dynamic library loading in Win XP/2003
	if (IsWindowsVistaOrGreater()) {
		HMODULE tcmalloc_module = LoadLibraryExW(L"tcmalloc.dll", 0, LOAD_WITH_ALTERED_SEARCH_PATH);
		if (tcmalloc_module) {
			LOAD(tcmalloc_module, tc_malloc);
			LOAD(tcmalloc_module, tc_realloc);
			LOAD(tcmalloc_module, tc_free);
		}
	}
#endif

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
