/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCSIO_CONFIG_H__
#define __PCSIO_CONFIG_H__

#include "pcs_types.h"
#include <fcntl.h>

#ifndef __WINDOWS__
#include <pthread.h>
#else
#include <sys/types.h>
#endif

/* --------------------------------------------------------------------------------------- */

#ifdef __LINUX__

#include <asm/unistd.h>
#include <features.h>

#define HAVE_FORK		1
#define HAVE_AIO		1
#define HAVE_POSIX_TIMER	1
#define HAVE_OOM_ADJUST		1
#define HAVE_PTHREAD_TIMEDJOIN	1
#define HAVE_TLS_STATIC		1

/* helpful link to find kernel/glibc version:
 * http://distrowatch.com/table.php?distribution=redhat */

#if __GLIBC_PREREQ(2, 4)
  #define HAVE_FSTATAT	1
  #define HAVE_TCP_INFO	1
#endif

/* RHEL5 doesn't have eventfd in glibc */
#if __GLIBC_PREREQ(2, 9)
  #define HAVE_EVENTFD	1
#endif

#endif	/* __LINUX__ */

/* --------------------------------------------------------------------------------------- */

#ifdef __MAC__
#define HAVE_FORK		1
#define HAVE_TLS_STATIC		1
#endif

/* --------------------------------------------------------------------------------------- */

#ifdef __SUN__
#define HAVE_FORK		1
/* Do not define HAVE_TLS_STATIC - otherwise gcc will cache TLS pointer.
 * This results in incorrect behaviour when coroutine is moved to another thread. */
#endif

/* --------------------------------------------------------------------------------------- */

#ifdef __GNUC__
#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#else
#define GCC_VERSION 0
#endif

#ifndef __GLIBC__
#define __GLIBC_PREREQ(mj,mi) 0
#endif

#ifdef __clang__
#if __clang_major__ >= 4
#if __has_feature(address_sanitizer)
#define PCS_ADDR_SANIT
#endif
#if __has_feature(thread_sanitizer)
#define PCS_THREAD_SANIT
#define __no_sanitize_thread	__attribute__((no_sanitize_thread))
#endif
#endif
#elif GCC_VERSION >= 70100
#if defined(__SANITIZE_ADDRESS__)
#define PCS_ADDR_SANIT
#endif
#if defined(__SANITIZE_THREAD__)
#define PCS_THREAD_SANIT
#define __no_sanitize_thread	__attribute__((no_sanitize_thread, noipa))
#endif
#endif
#ifdef PCS_THREAD_SANIT
void __tsan_acquire(void *);
void __tsan_release(void *);
#else
#define __no_sanitize_thread
#define __tsan_acquire(addr)
#define __tsan_release(addr)
#endif

#endif /* __PCSIO_CONFIG_H__ */
