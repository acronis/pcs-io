/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCS_TYPES_H__
#define __PCS_TYPES_H__

#include <stdint.h>

/* ----- platform macros ----- */

#ifdef __linux__
#define __LINUX__
#endif

#ifdef __APPLE__
#define __MAC__
#endif

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
#define __WINDOWS__
#endif

#ifdef __sparc__
#define __SPARC__
#endif

#ifdef __sun
#define __SUN__
#endif

/* ----- platform independant data types ----- */

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

#if defined(_WIN64)
  typedef unsigned __int64 ULONG_PTR;
#else
  typedef unsigned long ULONG_PTR;
#endif

#define llu long long unsigned int

/* ----- helpers ----- */
/* NOTE: use '__restrict' instead of C99 'restrict' as it is supported by all of: gcc, clang, msvc */
#if defined(__GNUC__) || defined(__clang__)

#define __printf(x,y)		__attribute__((format(printf, x, y), nonnull(x)))
#define __noreturn		__attribute__((noreturn))
#define __noinline		__attribute__((noinline))
#define __maybe_unused		__attribute__((unused))

#if !defined(__MINGW32__) && !defined(__MINGW64__)
#define __forceinline		inline __attribute__((always_inline))
#endif

#define __must_check		__attribute__((warn_unused_result))
#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)

#define container_of(ptr, type, member) ({                    \
		        const typeof( ((type *)0)->member ) *__ptr = (ptr);  \
		        (type *)( (char *)__ptr - offsetof(type,member) );})

#elif defined(_MSC_VER)

#define __printf(x,y)
#define __noreturn		__declspec(noreturn)
#define __noinline		__declspec(noinline)
#define __forceinline		__forceinline
#define __must_check		_Check_return_
#define likely(x)		(x)
#define unlikely(x)		(x)
/* MSVC doesn't compile "static inline", but is ok with "static __inline"... */
#define inline			__inline
#define __thread		__declspec(thread)
#define __maybe_unused

#define container_of(ptr, type, member) ((type*)((char*)(ptr) - offsetof(type, member)))

#endif

#ifdef __WINDOWS__

/* XXX: probably not the best place for this */
typedef unsigned long	sigset_t;
typedef void *		timer_t;

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

typedef HANDLE pcs_fd_t;
#define PCS_INVALID_FD INVALID_HANDLE_VALUE

#ifdef PCS_API_DLLEXPORT
#define PCS_API __declspec(dllexport)
#elif defined(PCS_API_DLLIMPORT)
#define PCS_API __declspec(dllimport)
#else
#define PCS_API
#endif

#else
typedef int pcs_fd_t;
#define PCS_INVALID_FD (-1)

#ifdef PCS_API_DLLEXPORT
#define PCS_API __attribute__((visibility("default")))
#else
#define PCS_API
#endif

#endif

#include "pcs_align.h"

typedef struct __pre_aligned(8) _PCS_NODE_ID_T {
	u64    val;
} PCS_NODE_ID_T __aligned(8);

typedef union {
	struct {
		u32 major;
		u32 minor;
	};
	u64 full;
} PCS_FAST_PATH_VERSION_T;

#endif /* __PCS_TYPES_H__ */
