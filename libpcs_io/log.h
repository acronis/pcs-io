/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCSLOG_H__
#define __PCSLOG_H__

/*
 * The module implements logging with advanced features like optional log
 * rotation and asynchronous writing to file.
 */

#include "pcs_types.h"
#include "bug.h"
#include "timer.h"
#include "pcs_compat.h"
#include "pcs_error.h"
#include <stdarg.h>

/*
 * Log level values and flags
 */
#define LOG_ERR		0
#define LOG_WARN	1
#define LOG_INFO	2
#define LOG_DEBUG	4
/* The high debug levels are used for dumping the system state */
#define LOG_DEBUG2	5
#define LOG_DEBUG3	6
/* Tracing levels */
#define LOG_TRACE	7
#define LOG_DEBUG4	8
#define LOG_DEBUG5	9
#define LOG_LEVEL_MAX	LOG_DEBUG5

/* The LOG_TRACE represents the 'production' level tracing which may be enabled by default.
 * So the next level is 'debug' level tracing
 */
#define LOG_DTRACE LOG_DEBUG4

/* Default log level */
#define LOG_LEVEL_DEFAULT LOG_WARN

/* Default log level for server (non-interactive) components */
#define LOG_LEVEL_SRV_DEFAULT LOG_TRACE

#define LOG_LEVEL_MASK	0x0FF
#define LOG_NONL	0x100	/* no default \n at the end */
#define LOG_NOIND	0x200	/* no indentation */
#define LOG_NOTS	0x400	/* no timestamp */
#define LOG_STDOUT	(0x800 | LOG_NOTS)	/* trace to stdout */

/* Global variables */
#ifdef __WINDOWS__
/* On Windows delay load flow doesn't work with exported variables */
PCS_API int *pcs_log_lvl(void);
#define pcs_log_level (*pcs_log_lvl())
#else
PCS_API extern int __pcs_log_level;
#define pcs_log_level __pcs_log_level
#endif

PCS_API int *pcs_log_indent(void);
#define log_indent (*pcs_log_indent())

/* Returns true if pcs_log_level is not enough to print messages with a given verbosity level */
static inline int pcs_log_quiet(int level)
{
	return likely((pcs_log_level & LOG_LEVEL_MASK) < level);
}

/*
 * The basic log API
 */

/* Log message formatting routines */
PCS_API void pcs_log(int level, const char *fmt, ...) __printf(2, 3);
PCS_API void pcs_valog(int level, const char *prefix, const char *fmt, va_list va);
PCS_API void pcs_log_hexdump(int level, const void *buf, int len);

PCS_API void pcs_trace(int level, const char* func, const char *fmt, ...) __printf(3, 4);

/* Debug routines */
PCS_API void __noreturn pcs_err(const char *msg, const char *file, int line, const char *func);
PCS_API void __noreturn pcs_fatal(const char *fmt, ...) __printf(1,2);
PCS_API void show_trace(void);

struct pcs_ucontext;
void show_trace_coroutine(struct pcs_ucontext *ctx);

/* Register product version to print on traces */
PCS_API void pcs_log_version_register(const char *version);
/* Get registered product versions */
PCS_API int pcs_log_get_registered_versions(const char *versions[], int sz);

/* Fill buffer with formatted time. */
int pcs_log_format_time(abs_time_t ts, char* buff, unsigned sz);
int __pcs_log_format_time_std(abs_time_t ts, char* buff, unsigned sz, char *saved_time_buff, time_t *current_sec);

#define PCS_LOG_ROTATE_MASK		0x7
#define PCS_LOG_PRINT_LEVEL		(1 << 3)

/* Direct log output to the file and switch to buffered asynchronous writing scheme.
 * This function may be called only once. It is expected to be called at the application startup.
 * Only one of two functions: pcs_set_logfile[_ex]() or pcs_set_log_handler() must be called.
 *
 * prefix: file name prefix (includes directory). See comments in pcs_log_rotate_t for
 *   filename formats.
 * compression: "gz", "zst" or "" (empty string)
 * rotate_mode: PCS_LOG_ROTATE_ENUM or PCS_LOG_ROTATE_MULTIPROC
 * id: include this numeric id to filename. If 0 - use PID, if > 0 - use
 * this id (PCS_LOG_ROTATE_MULTIPROC mode only) */
PCS_API int pcs_set_logfile_ex(const char *prefix, const char *compression, int flags);

/* pcs_set_logfile_ex with PCS_LOG_TS_STD timestamps format */
PCS_API int pcs_set_logfile(const char * path);

/* Returns currently used log file or NULL if it was not set yet */
const char* pcs_get_logfile(void);

/* Returns currently used logfile path split onto the basename part and extension.
 * The returned basename part must be freed by caller passing them to pcs_free().
 */
char* pcs_get_logfile_base_ext(const char** pext);
extern const char *log_exts[];

/* Direct log output to the function handler(level, fmt, va).
 * This function may be called only once. It is expected to be called at the application startup.
 * Only one of two functions: pcs_set_logfile() or pcs_set_log_handler() must be called.
 * The log rotation is disabled in case log handler is set. */
PCS_API void pcs_set_log_handler(void (*handler)(int level, int indent, const char *prefix, const char *fmt, va_list va));

/* Write buffered data data to disk and terminate writer thread. */
PCS_API void pcs_log_terminate(void);

/* Fill provided buffer with buffered log tail or returns -1 if log is not buffered. */
int pcs_log_get_tail(char* buff, unsigned* sz);

#ifndef __WINDOWS__
#include <signal.h>

/* Terminate log on fatal signals gracefully */
void pcs_log_fatal_sighandler(int sig, siginfo_t *info, void *context);
#else /* __WINDOWS__ */
extern LPTOP_LEVEL_EXCEPTION_FILTER old_fatal_handler;
LONG __stdcall pcs_log_fatal_sighandler(EXCEPTION_POINTERS *ptrs);
#endif

/* Asynchronous interface for system log */
struct pcs_syslog_logger;
struct pcs_process;

void pcs_syslog(struct pcs_syslog_logger *l, int priority, const char *fmt, ...) __printf(3, 4);
int pcs_syslog_open(struct pcs_process *proc, const char *name, struct pcs_syslog_logger **logger);
void pcs_syslog_close(struct pcs_syslog_logger *l);

/* PCS_LOG_ROTATE_ENUM mode only */
PCS_API void pcs_set_logrotate_size(unsigned long long size);
PCS_API void pcs_set_logrotate_filenum(unsigned int filenum);

/* PCS_LOG_ROTATE_MULTIPROC mode only */
PCS_API void pcs_set_logrotate_limits(unsigned long long rotate_size, int nfiles, unsigned long long total_size, abs_time_t max_age_sec);
PCS_API void pcs_apply_log_files_limits(int nfiles, unsigned long long total_size, abs_time_t age_sec);

PCS_API void pcs_ext_logrotate_sighandler(int signum);
void pcs_ext_logrotate_force(void);

/* The exit message file may optionally contain the postmortem message from application to management tools. */
void pcs_set_exitmsg_file(char *path);
void pcs_log_exitmsg(const char *fmt, ...) __printf(1,2);

/*
 * Tracing
 */

#define TRACE_(l, ...)	pcs_trace((l), __FUNCTION__, __VA_ARGS__)

#define TRACE0()        TRACE_(LOG_TRACE, NULL)
#define TRACE(...)  TRACE_(LOG_TRACE, __VA_ARGS__)
#define DTRACE0()       TRACE_(LOG_DTRACE, NULL)
#define DTRACE(...) TRACE_(LOG_DTRACE, __VA_ARGS__)

#define TRACE_ACTIVE_(l) (pcs_log_level >= (l))
#define TRACE_ACTIVE TRACE_ACTIVE_(LOG_TRACE)

char* get_basename_ext(const char* fname, const char** pext);
char * format_filename_ts(const char *basename, const char *ext, unsigned long id);

#endif /* __PCSLOG_H__ */
