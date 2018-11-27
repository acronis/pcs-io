/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCSIO_COMPAT_H__
#define __PCSIO_COMPAT_H__

#include "pcs_types.h"
#include "pcs_config.h"
#include <sys/types.h>

#if defined(__WINDOWS__) || defined(__SUN__)
#include <sys/stat.h>

#define DT_UNKNOWN      0
#define DT_FIFO		1
#define DT_CHR		2
#define DT_DIR		4
#define DT_BLK		6
#define DT_REG		8
#define DT_LNK		10
#define DT_SOCK		12
#define DT_WHT		14

#define IFTODT(m)       (((m) & S_IFMT) >> 12)
#define DTTOIF(t)       ((t) << 12)
#endif

#ifdef __WINDOWS__
#define S_IFIFO		DTTOIF(DT_FIFO)
#define S_IFBLK		DTTOIF(DT_BLK)
#define S_IFLNK		DTTOIF(DT_LNK)
#define S_IFSOCK	DTTOIF(DT_SOCK)

#define S_ISUID		0x800
#define S_ISGID		0x400
#define S_ISVTX		0x200

#define S_IRUSR		S_IREAD
#define S_IWUSR		S_IWRITE
#define S_IXUSR		S_IEXEC
#define S_IRWXU		(S_IREAD | S_IWRITE | S_IEXEC)

#define S_IRGRP		(S_IRUSR >> 3)
#define S_IWGRP		(S_IWUSR >> 3)
#define S_IXGRP		(S_IXUSR >> 3)
#define S_IRWXG		(S_IRWXU >> 3)

#define S_IROTH		(S_IRGRP >> 3)
#define S_IWOTH		(S_IWGRP >> 3)
#define S_IXOTH		(S_IXGRP >> 3)
#define S_IRWXO		(S_IRWXG >> 3)

#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)

#define O_ACCMODE	(O_RDONLY | O_WRONLY | O_RDWR)
#define O_DIRECT	0x40000000

#define F_RDLCK		1
#define F_UNLCK		2
#define F_WRLCK		3

#define F_SETLK		6
#define F_SETLKW	7

struct iovec {
    void	*iov_base;
    size_t	iov_len;
};

#else /* __WINDOWS__ */

#include <fcntl.h>

#if defined(__LINUX__) && __GLIBC_PREREQ(2, 8)
#define HAVE_SYNC_FILE_RANGE
#endif

#ifndef O_DIRECT
#define O_DIRECT	0
#endif

#ifndef F_OFD_SETLK

#if defined(__LINUX__)
#define F_OFD_SETLK	37
#define F_OFD_SETLKW	38
#elif defined(__MAC__)
/* https://github.com/apple/darwin-xnu/blob/xnu-3247.1.106/bsd/sys/fcntl.h#L353 */
#define F_OFD_SETLK	90
#define F_OFD_SETLKW	91
#endif

#endif /* F_OFD_SETLK */

#endif /* __WINDOWS__ */

PCS_API unsigned int pcs_nr_processors(void);
PCS_API unsigned int pcs_sys_page_size(void);
PCS_API u64 pcs_phys_memory_size(void);

#ifdef __WINDOWS__
PCS_API int fsync(int fd);
PCS_API int ftruncate(int fd, u64 len);
PCS_API char *strndup(const char *s, size_t size);

#if (_MSC_VER < 1900) && !defined(snprintf)
#include <stdio.h>

PCS_API int pcs_vsnprintf(char *str, size_t size, const char *format, va_list ap);
PCS_API int pcs_snprintf(char *str, size_t size, const char *format, ...);

#define vsnprintf pcs_vsnprintf
#define snprintf pcs_snprintf
#endif /* _MSC_VER < 1900 */

/* For null-terminated string -1 can be used as len.
   Returns (m)allocated widechar string or null. Check GetLastError() for failure reason. */
PCS_API WCHAR * pcs_utf8_to_utf16(const char * str, int len);
PCS_API char * pcs_utf16_to_utf8(const WCHAR * wstr, int wlen);

#define strtok_r strtok_s

#endif /* _MSC_VER */

#endif /* __PCSIO_COMPAT_H__ */
