/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_compat.h"
#include "pcs_config.h"
#include "pcs_malloc.h"
#include "pcs_types.h"
#include "bug.h"

#ifndef __WINDOWS__
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#ifdef __MAC__
#include <sys/sysctl.h>
#endif
#else
#include <io.h>		/* _get_osfhandle */
#include <errno.h>
#endif

#ifdef __WINDOWS__
int fsync(int fd)
{
	HANDLE h = (HANDLE)_get_osfhandle(fd);
	if (h == INVALID_HANDLE_VALUE)
		return -1;

	if (!FlushFileBuffers(h))
		return -1;

	return 0;
}

int ftruncate(int fd, u64 len)
{
	int err = _chsize_s(fd, len);
	if (err) {
		errno = err;
		return -1;
	}
	return 0;
}

char * strndup(const char *str, size_t n)
{
	size_t len;
	char *copy;

	len = strnlen(str, n);
	if ((copy = malloc(len + 1)) == NULL)
		return (NULL);
	memcpy(copy, str, len);
	copy[len] = '\0';
	return (copy);
}

WCHAR * pcs_utf8_to_utf16(const char * str, int len)
{
	int w_len = MultiByteToWideChar(CP_UTF8, 0, str, len, NULL, 0);
	if (w_len == 0)
		return NULL;

	WCHAR * w_str = pcs_xmalloc(sizeof(WCHAR) * (w_len + 1));
	int res = MultiByteToWideChar(CP_UTF8, 0, str, len, w_str, w_len);
	BUG_ON(res != w_len);
	w_str[w_len] = L'\0';
	return w_str;
}

char * pcs_utf16_to_utf8(const WCHAR * wstr, int wlen)
{
	int len = WideCharToMultiByte(CP_UTF8, 0, wstr, wlen, NULL, 0, NULL, NULL);
	if (len == 0)
		return NULL;

	char * str = pcs_xmalloc(len + 1);
	int res = WideCharToMultiByte(CP_UTF8, 0, wstr, wlen, str, len, NULL, NULL);
	BUG_ON(res != len);
	str[len] = '\0';
	return str;
}

int pcs_vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
	int count = -1;

	if (size != 0) {
		count = _vsnprintf(str, size, format, ap);
		str[size - 1] = 0;
	}
	if (count == -1) {
		count = _vscprintf(format, ap);
	}

	return count;
}

int pcs_snprintf(char *str, size_t size, const char *format, ...)
{
	int count;
	va_list ap;

	va_start(ap, format);
	count = pcs_vsnprintf(str, size, format, ap);
	va_end(ap);

	return count;
}
#endif /* __WINDOWS__ */

unsigned int pcs_nr_processors(void)
{
#ifdef __WINDOWS__
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	return info.dwNumberOfProcessors;
#else
	int nr = sysconf(_SC_NPROCESSORS_ONLN);
	return (nr <= 0) ? 1 : nr;
#endif
}

unsigned int pcs_sys_page_size(void)
{
#ifdef __WINDOWS__
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	return info.dwPageSize;
#else
	int nr = sysconf(_SC_PAGESIZE);
	return (nr <= 0) ? 4096 : nr;
#endif
}

u64 pcs_phys_memory_size(void)
{
#if defined(__WINDOWS__)
	MEMORYSTATUS mem;
	GlobalMemoryStatus(&mem);
	return mem.dwTotalPhys;
#elif defined(__MAC__)
	int mib[2] = { CTL_HW, HW_MEMSIZE };
	u64 mem_size = 0;
	size_t len = sizeof(mem_size);
	return sysctl(mib, 2, &mem_size, &len, 0, 0) < 0 ? 0 : mem_size;
#else
	long phys_pages = sysconf(_SC_PHYS_PAGES);
	long pg_size = sysconf(_SC_PAGESIZE);
	if (phys_pages < 0 || pg_size < 0)
		return 0;
	return (u64)phys_pages * pg_size;
#endif
}
