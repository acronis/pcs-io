/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#pragma once

#include <features.h>
#if (__GLIBC__ == 2 && __GLIBC_MINOR__ < 9)

#ifndef __linux__
#error This file may be compiled on Linux only.
#endif

#ifndef __NR_signalfd
#if defined (__i386__)
#define __NR_signalfd 321
#elif defined (__x86_64__)
#define __NR_signalfd 282
#endif
#endif

#ifndef __NR_signalfd4
#if defined (__i386__)
#define __NR_signalfd4 327
#elif defined (__x86_64__)
#define __NR_signalfd4 289
#endif
#endif

#include <signal.h>
#include <stdint.h>
#include <unistd.h>

struct signalfd_siginfo
{
	uint32_t ssi_signo;
	int32_t ssi_errno;
	int32_t ssi_code;
	uint32_t ssi_pid;
	uint32_t ssi_uid;
	int32_t ssi_fd;
	uint32_t ssi_tid;
	uint32_t ssi_band;
	uint32_t ssi_overrun;
	uint32_t ssi_trapno;
	int32_t ssi_status;
	int32_t ssi_int;
	uint64_t ssi_ptr;
	uint64_t ssi_utime;
	uint64_t ssi_stime;
	uint64_t ssi_addr;
	uint8_t __pad[48];
};

/* Flags for signalfd.  */
enum
{
	SFD_CLOEXEC = 02000000,
#define SFD_CLOEXEC SFD_CLOEXEC
	SFD_NONBLOCK = 04000
#define SFD_NONBLOCK SFD_NONBLOCK
};

static inline int pcs_signalfd(int fd, const sigset_t *mask, int flags)
{
#if defined __NR_signalfd4
	int rv = syscall(__NR_signalfd4, fd, mask, (size_t)8, flags);
	if (rv < 0) {
		if (flags != 0) {
			errno = EINVAL;
			return -1;
		}
		rv = syscall(__NR_signalfd, fd, mask, (size_t)8);
	}
	return rv;
#elif defined __NR_signalfd
	return syscall(__NR_signalfd, fd, mask, (size_t)8);
#else
	errno = ENOSYS;
	return -1;
#endif
}
#else
#include <sys/signalfd.h>
static inline int pcs_signalfd (int fd, const sigset_t *mask, int flags)
{
	return signalfd(fd, mask, flags);
}

#endif

