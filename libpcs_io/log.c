/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

/*
 * The module implements logging with advanced features like optional log
 * rotation and asynchronous writing to file.
 */

#include "pcs_config.h"
#include "pcs_types.h"
#include "pcs_profiler.h"
#include "log.h"
#include "logrotate.h"
#include "crc32.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

/* Log level and formatting global flags */
int __pcs_log_level = LOG_LEVEL_DEFAULT;
#ifdef HAVE_TLS_STATIC
static __thread int __log_indent;
#else
static int __log_indent;
#endif

#define VERSION_LIST_MAX 8
static int version_nr;
static const char * version_list[VERSION_LIST_MAX];

#define PCS_LOG_ENABLED

#ifdef PCS_LOG_ENABLED

#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef __WINDOWS__
#include <time.h>
#include <io.h>

LPTOP_LEVEL_EXCEPTION_FILTER old_fatal_handler = NULL;
#else /* __WINDOWS__ */
#include <sys/time.h>
#include <unistd.h>
#endif /* __WINDOWS__ */
#ifdef PCS_ADDR_SANIT
#include <sanitizer/lsan_interface.h>
#endif

#include "pcs_error.h"
#include "pcs_thread.h"
#include "pcs_malloc.h"
#include "pcs_sync_io.h"
#include "pcs_sock.h"	/* for struct timeval on Windows */
#include "regdump.h"
#include "timer.h"

#define _ENABLE_GZIP_COMPRESSION 1

#ifdef _ENABLE_GZIP_COMPRESSION
#include <zlib.h>
#define GZIP_COMPRESSION_LEVEL	"w5"
#endif

#ifdef _ENABLE_ZSTD_COMPRESSION
#include <zstd.h>
#define ZSTD_COMPRESSION_LEVEL 3
#define ZSTD_ERR_MSG_MAX 256

struct zst_wrap {
	char msg[ZSTD_ERR_MSG_MAX];
	void *compress_buff;
	int compress_buff_size;
};
#endif

/* timestamp definitions */
#define SHORT_TIME_LEN		10

/*
 * The asynchronous log writer context definitions
 */

#define LOG_BUFF_SZ		0x100000
#define LOG_BUFF_RESERVE	0x10000
#define LOG_BUFF_THRESHOLD	(LOG_BUFF_SZ-LOG_BUFF_RESERVE)
#define LOG_BUFF_NEXT(Ind)	(((Ind) + 1) % 2)
#define LOG_BUFF_PREV(Ind)	LOG_BUFF_NEXT(Ind)

#define __str(s) #s
#define __xstr(s) __str(s)

#define	LOGGER_ERR(...) do { \
		char time_buff[32]; \
		pcs_log_format_time(get_real_time_ms(), time_buff, sizeof(time_buff)); \
		fprintf(stderr,  "%s: ERROR (" __FILE__ ":" __xstr(__LINE__) "): ", time_buff); \
		fprintf(stderr,  __VA_ARGS__); \
	} while (0)
#define ARRAY_SIZE(a)  (sizeof(a) / sizeof(*(a)))

const char log_level_names[] = {'E', 'W', 'I', 'T', 'T', 'T', 'T', 'D', 'D'};
BUILD_BUG_ON(ARRAY_SIZE(log_level_names) != LOG_LEVEL_MAX);

struct log_buff {
	char		buff[LOG_BUFF_SZ];

	unsigned	used;	/* The number of used bytes */
	unsigned	full;	/* Set to the number of bytes if writing is pending */
};

struct log_writer {
	/* The current filename */
	char*		fname;
	int             lflags; 

	/* The lock file descriptor */
	pcs_fd_t	lock_fd;
	/* The file descriptor */
	pcs_fd_t	fd;
#ifdef _ENABLE_GZIP_COMPRESSION
	gzFile		gz_file;
#endif
#ifdef _ENABLE_ZSTD_COMPRESSION
	struct zst_wrap	zst;
#endif
	/* Worker thread */
	pcs_thread_t	worker;

	/* Condition to wait on */
	pthread_cond_t	cond;
	pthread_condattr_t condattr;

	/* Current log on-disk size */
	long long 	log_size;

	/* Termination request */
	int		close_request;

	/* The double buffering stuff */
	int		curr;	/* Current buffer index */
	int		written;/* Last written buffer index */
	struct log_buff	b[2];

	int (*open_log)(struct log_writer* l);
	void (*write_buff)(struct log_writer* l, struct log_buff* b);
	void (*close_log)(struct log_writer* l);
	int (*reopen_log)(struct log_writer* l);

	struct logrotate	rotate;
};

/* Set after client placed message with LOG_NONL flag. It indicates the client intention to continue writing
 * the log in single line. It also prevents flushing the log content. Not quite thread safe but simple enough.
 */
static int log_nonl;

/* Log writer context. The context is not allocated in case of the default stderr logging.
 * The log rotation is disabled in such case as well.
 */
static struct log_writer* logwriter;

/* Supported extentions for log rotation */
const char *log_exts[] = { ".gz", ".zst", ".log", ".blog", "", NULL };

#ifdef __WINDOWS__
struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
	if (gmtime_s(result, timep))
		return NULL;

	return result;
}

struct tm *localtime_r(const time_t *timep, struct tm *result)
{
	if (localtime_s(result, timep))
		return NULL;

	return result;
}
#endif

/* Alternate log writer backend. When this function is set logwriter is not used.
 * The log rotation is disabled in such case as well.
 */
static void (*log_handler)(int level, int indent, const char *prefix, const char *fmt, va_list va);

static void init_ops_generic(struct log_writer* l);

static void write_log_header(struct log_writer *l);

#if defined(_ENABLE_GZIP_COMPRESSION) || defined(_ENABLE_ZSTD_COMPRESSION)
static struct z_funcs_s {
	int (*open_existing)(int fd, u64 size, struct log_writer *log);
	int (*dopen)(struct log_writer* l, pcs_fd_t fd);
	int (*close)(struct log_writer* l);
	int (*file_is_null)(struct log_writer* l);
	int (*write)(struct log_writer* l, const void* buff, int len);
	const char* (*get_error)(struct log_writer* l, int *errnum);
	int (*puts)(struct log_writer* l, char *str);
	void (*clear_err)(struct log_writer* l);
	int (*flush)(struct log_writer* l);
} z_funcs = {0};
#endif
#ifdef _ENABLE_GZIP_COMPRESSION
static void init_ops_gzip(struct log_writer* l);
#endif
#ifdef _ENABLE_ZSTD_COMPRESSION
static void init_ops_zstd(struct log_writer* l);
#endif

/* The access to the log from the client threads will be serialized */
static pthread_mutex_t loglock =
#if defined(__linux__)
	PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
#else
	/* FIXME: MacOS doesn't support recursive locking, so logging may hang somewhere below on catching of SIGSEGV etc. */
	PTHREAD_MUTEX_INITIALIZER;
#endif
/* Prevent race between logger thread and fatal signal handler
 * for flushing the log */
static pthread_mutex_t flushlock = PTHREAD_MUTEX_INITIALIZER;
static int in_fatal_signal_handler = 0;

static inline int log_writer_active(void)
{
	return logwriter && !logwriter->close_request;
}

static inline abs_time_t lock_log(void)
{
	pthread_mutex_lock(&loglock);
	if (log_writer_active())
	{
		/* If the current buffer is full wait for write completion */
		if (logwriter->b[logwriter->curr].full) {
			abs_time_t ts1;

			ts1 = get_abs_time_ms();
			do
				pthread_cond_wait(&logwriter->cond, &loglock);
			while (logwriter->b[logwriter->curr].full);
			return get_elapsed_time(get_abs_time_ms(), ts1);
		}
	}

	return 0;
}

static inline void unlock_log(void)
{
	if (!log_nonl)
	{
		/* Flush log */
		if (log_writer_active())
		{
			struct log_buff* b = &logwriter->b[logwriter->curr];
			BUG_ON(b->full);
			if (b->used >= LOG_BUFF_THRESHOLD) {
				/* If filled switch current buffer and wake up writer */
				b->full = b->used;
				logwriter->curr = LOG_BUFF_NEXT(logwriter->curr);
				logwriter->b[logwriter->curr].used = 0;
				pthread_cond_broadcast(&logwriter->cond);
			}
		} else
			fflush(stderr);
	}
	pthread_mutex_unlock(&loglock);
}

/* posix file operations */
static int log_file_open(const char *filename, int flag, int pmode)
{
#ifdef __WINDOWS__
	return _open(filename, _O_BINARY | flag, pmode);
#else /* __WINDOWS__ */
	return open(filename, flag, pmode);
#endif /* __WINDOWS__ */
}

static int log_fname_lock(struct log_writer *l)
{
	int res;

	if ((l->lflags & PCS_LOG_ROTATE_MASK) != PCS_LOG_ROTATE_ENUM)
		return 0;

	/* As l->fname is a const field so such lock_fd initialization is ok */
	/* lock_fd was initialized PCS_INVALID_FD in pcs_set_logfile; First time here, set locked .lck file */
	if (l->lock_fd != PCS_INVALID_FD)
		return 0;

	if ((res = pcs_sync_create_lock_file(l->fname, &l->lock_fd)) < 0) {
		pcs_log(LOG_ERR, "failed to lock log file: %d (%s)", -res, strerror(-res));
		return -1;
	}

	return 0;
}

static int log_file_close(int fd)
{
#ifdef __WINDOWS__
	return _close(fd);
#else /* __WINDOWS__ */
	return close(fd);
#endif /* __WINDOWS__ */
}


static int log_file_getsize(int fd, u64* size)
{
#ifdef __WINDOWS__
	struct _stat64 st;
	if (_fstat64(fd, &st) < 0)
		return -1;
	*size = (u64)st.st_size;
#else /* __WINDOWS__ */
	struct stat st;
	if (fstat(fd, &st) < 0)
		return -errno;
	*size = st.st_size;
#endif /* __WINDOWS__ */
	return 0;
}

static int log_file_dup(int fd)
{
#ifdef __WINDOWS__
	return _dup(fd);
#else /* __WINDOWS__ */
	return dup(fd);
#endif /* __WINDOWS__ */
}

static int log_file_ftruncate(int fd, u64 offs)
{
#ifdef __WINDOWS__
	errno_t res = _chsize_s(fd, (__int64)offs);
	if (res) {
		errno = res;
		return - 1;
	}
	return 0;
#else /* __WINDOWS__ */
	int res = 0;
	while ((res = ftruncate(fd, offs)) < 0 && errno == EINTR);
	return res;
#endif /* __WINDOWS__ */
}

static s64 log_file_lseek(int fd, u64 offset, int origin)
{
#ifdef __WINDOWS__
	return _lseeki64(fd, (__int64)offset, origin);
#else /* __WINDOWS__ */
	return lseek(fd, (off_t)offset, origin);
#endif /* __WINDOWS__ */
}

static s32 log_file_read(int fd, void* buff, u32 count)
{
#ifdef __WINDOWS__
	return (s32)_read(fd, buff, count);
#else /* __WINDOWS__ */
	return (s32)read(fd, buff, count);
#endif /* __WINDOWS__ */
}

static void __noreturn pcs_abort(void)
{
	pcs_log_terminate();

	/* block profiler signals to avoid truncated core dumps */
	pcs_profiler_block(NULL, NULL);

	abort();
}

/* ----------------------------------------------------------------------------------------------------
 * The core time formatting routines
 * ---------------------------------------------------------------------------------------------------- */

#define STD_TIME_FMT "%Y-%m-%d %H:%M:%S"
#define STD_TIME_LEN 19

int __pcs_log_format_time_std(abs_time_t ts, char* buf, unsigned sz, char *saved_time_buf, time_t *current_sec)
{
	/* if saved_time_buf and current_sec are NULL, function will each time
	 * run localtime. else saved_time_buf will be used for filling buf,
	 * if current_sec is equal to sec, current_sec will be updated.
	 * *current_sec must equal to 0 (first time), or value, which was returned
	 * this function
	 */
	time_t sec = ts / 1000;
	struct tm tm;

	if (sz < STD_TIME_LEN + 4 /* for milliseconds */ + 1 /* \0 */) pcs_abort(); // don't use BUG_ON - recursion

	if (saved_time_buf && current_sec)
	{
		if (sec != *current_sec) {
			*current_sec = sec;
			if (!localtime_r(&sec, &tm)) pcs_abort(); // don't use BUG_ON - recursion
			size_t len = strftime(saved_time_buf, sz, STD_TIME_FMT, &tm);
			if (len != STD_TIME_LEN) pcs_abort(); // don't use BUG_ON - recursion
		}
		memcpy(buf, saved_time_buf, STD_TIME_LEN);
	} else {
		if (!localtime_r(&sec, &tm)) pcs_abort(); // don't use BUG_ON - recursion
		size_t len = strftime(buf, sz, STD_TIME_FMT, &tm);
		if (len != STD_TIME_LEN) pcs_abort(); // don't use BUG_ON - recursion
	}

	abs_time_t msec = ts - sec * 1000ULL;
	buf += STD_TIME_LEN;
	*buf++ = '.';
	*buf++ = '0' + msec / 100;
	*buf++ = '0' + (msec / 10) % 10;
	*buf++ = '0' + msec % 10;
	*buf++ = 0;

	return STD_TIME_LEN + 4;
}

int pcs_log_format_time(abs_time_t ts, char* buf, unsigned sz)
{
	return __pcs_log_format_time_std(ts, buf, sz, NULL, NULL);
}

#define COMPACT_TIME_FMT "%Y%m%dT%H%M"
#define COMPACT_TIME_LEN 13

int __pcs_log_format_time_compact(abs_time_t ts, char* buf, unsigned sz)
{
	time_t ts_sec = ts / 1000;
	struct tm tm;

	/* Shouldn't fail, ts_sec must be valid always */
	if (!gmtime_r(&ts_sec, &tm)) pcs_abort(); // don't use BUG_ON - recursion

	size_t len = strftime(buf, sz, COMPACT_TIME_FMT, &tm);
	if (len != COMPACT_TIME_LEN) pcs_abort(); // don't use BUG_ON - recursion
	return COMPACT_TIME_LEN;
}

char * format_filename_ts(const char *basename, const char *ext, unsigned long id)
{
	abs_time_t ts;
	char ts_str[COMPACT_TIME_LEN + 1];

	ts = get_real_time_ms();
	__pcs_log_format_time_compact(ts, ts_str, sizeof(ts_str));

	return pcs_xasprintf("%s-%s.%lu%s", basename, ts_str, id, ext);
}

/* ----------------------------------------------------------------------------------------------------
 * The core log output routines
 * ---------------------------------------------------------------------------------------------------- */

static void __log_vprintf_stdfile(FILE *f, int level, const char *prefix, const char *fmt, va_list va)
{
	if (!(level & LOG_NOTS)) {
		char ts[32];
		static char last_time_buff[32];
		static time_t last_second = 0;
		__pcs_log_format_time_std(get_real_time_ms(), ts, sizeof(ts), last_time_buff, &last_second);
		fprintf(f, "%s ", ts);
	}

	if (prefix) {
		fprintf(f, "%s: ", prefix);
	}
	if (fmt) {
		vfprintf(f, fmt, va);
	}
	if (!(level & LOG_NONL)) {
		fputs("\n", f);
	}
}

static void __log_vprintf_buf(int level, const char *prefix, const char *fmt, va_list va)
{
	/* Consider current buffer */
	struct log_buff *b = &logwriter->b[logwriter->curr];
	int sz = LOG_BUFF_SZ - b->used - 32 /* max timestamp */ - 1 /* log level */ - 1 /* space */ - 64 /* max prefix */ - 48 /* max indent */ - 1 /* \n */;
	if (b->full || sz < 0) {
		/* NOTE: these functions should not use BUG_ON, recursive loop is possible as BUG_ON will call us again. */
		pcs_abort();
	}

	if (!(level & LOG_NOTS)) {
		static char last_time_buff[32];
		static time_t last_second = 0;
		abs_time_t t = get_real_time_ms();
		int ts_len;

		if (!logwriter) pcs_abort(); // don't use BUG_ON - recursion
		ts_len = __pcs_log_format_time_std(t, &b->buff[b->used], 32, last_time_buff, &last_second);

		b->used += ts_len;
		b->buff[b->used++] = ' ';
	}

	/* LOG_NOTS actually means that previous print was with LOG_NONL */
	if (!(level & LOG_NOTS) && logwriter->lflags & PCS_LOG_PRINT_LEVEL) {
		int name_idx = (level & LOG_LEVEL_MASK) > LOG_LEVEL_MAX ? LOG_LEVEL_MAX : level & LOG_LEVEL_MASK;
		b->buff[b->used++] = log_level_names[name_idx];
		b->buff[b->used++] = ' ';
	}

	if (__log_indent && !(level & LOG_NOIND)) {
		const char indent[] = "                                                ";
		int len = __log_indent < sizeof(indent) ? __log_indent : sizeof(indent) - 1;
		memcpy(&b->buff[b->used], indent, len);
		b->used += len;
	}

	if (prefix) {
		size_t len = strlen(prefix);
		len = len < 64 ? len : 64;
		memcpy(&b->buff[b->used], prefix, len);
		b->used += len;
		b->buff[b->used++] = ':';
		b->buff[b->used++] = ' ';
	}

	if (fmt) {
		/* Output to the buffer */
		int res = vsnprintf(&b->buff[b->used], sz, fmt, va);
		if (res < 0) {
			/* Output error */
			res = snprintf(&b->buff[b->used], sz, "!!! LOG FORMAT ERROR: %s\n", fmt);
		}
		else if (res > sz) {
			/* Output is truncated. It means that the client is writing
			 * more than LOG_BUFF_RESERVE in single log line.
			 */
			res = snprintf(&b->buff[b->used], sz, "!!! LOG MESSAGE TOO LONG: %s\n", fmt);
		}
		if (res < 0) {
			res = 0;
		} else if (res > sz) {
			res = sz;
		}
		/* Update used buffer space */
		b->used += res;
	}

	if (!(level & LOG_NONL)) {
		b->buff[b->used++] = '\n';
	}
}

static void log_vprintf_lvl(int level, const char *prefix, const char *fmt, va_list va)
{
	/* special case when handler set - its duty is to print TS, prefix/indent */
	if (log_handler) {
		log_handler(level, (level & LOG_NOIND) ? 0 : __log_indent, prefix, fmt, va);
		return;
	}

	if ((level & LOG_STDOUT) == LOG_STDOUT) {
		__log_vprintf_stdfile(stdout, level, prefix, fmt, va);
		return;
	}

	/* Just redirect to stderr if file writer is not allocated or already terminating*/
	if (!log_writer_active()) {
		__log_vprintf_stdfile(stderr, level, prefix, fmt, va);
		return;
	}

	__log_vprintf_buf(level, prefix, fmt, va);
}

/* log_printf should be used under log lock or in extreme cases (crash). unlike printf, it adds \n at the end. */
static void log_printf(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	log_vprintf_lvl(LOG_ERR, NULL, fmt, va);
	va_end(va);
}

/*
 * The log worker
 */

static int __open_log_file(struct log_writer* l)
{
	pcs_fd_t fd = 0;
	int rc = 0;
	u64 size = 0;
	BUG_ON(!l->fname);
	if (log_fname_lock(l) < 0)
		return -1;

	if ((rc = pcs_sync_open(l->fname, O_WRONLY | O_CREAT | O_APPEND, 0666, &fd))) {
		pcs_log(LOG_ERR, "failed to open log file %s : %s", l->fname, strerror(-rc));
		return -1;
	}
	if ((rc = pcs_sync_lseek(fd, 0, SEEK_END, &size)) < 0) {
		pcs_log(LOG_ERR, "seek failed on log file %s : %s", l->fname, strerror(-rc));
		pcs_sync_close(fd);
		return -1;
	}
	l->fd = fd;
	l->log_size = size;
	return 0;
}

static void __write_log_buff(struct log_writer* l, struct log_buff* b)
{
	int size = b->full;
	BUG_ON(!size);
	BUG_ON(size > LOG_BUFF_SZ);
	if (pcs_sync_nwrite(l->fd, l->log_size, b->buff, size) == size) {
		l->log_size += size;
	} else {
		fprintf(stderr, "failed to write %d bytes to %s : %s\n", size, l->fname, strerror(errno));
		fflush(stderr);
	}
}

static void log_worker_write(struct log_writer* l)
{
	for (;;)
	{
		int next_buff = LOG_BUFF_NEXT(l->written);
		struct log_buff* b = &l->b[next_buff];
		if (!b->full)
			return;

		pthread_mutex_lock(&flushlock);
		l->write_buff(l, b);
		pthread_mutex_lock(&loglock);
		b->full = 0;
		/* dev@: shit... AFAICS the same cond is used to wakeup log_worker and blocked users... can it work?... */
		pthread_cond_broadcast(&l->cond);
		pthread_mutex_unlock(&loglock);
		l->written = next_buff;
		pthread_mutex_unlock(&flushlock);
	}
}

static void __log_worker_close(struct log_writer* l)
{
	int res = pcs_sync_close(l->fd);
	if (res)
		pcs_log(LOG_ERR, "failed to close log file %s : %s", l->fname, strerror(-res));
	l->fd = (pcs_fd_t)(-1);
}

static int __log_worker_reopen(struct log_writer* l)
{
	pcs_fd_t fd = l->fd;
	int res = l->open_log(l);
	if (res)
		return -1;
	res = pcs_sync_close(fd);
	if (res) {
		pcs_log(LOG_ERR, "failed to close log file %s : %s", l->fname, strerror(-res));
		return -1;
	}
	return 0;
}

char* get_basename_ext(const char* fname, const char** pext)
{
	char *base_name = pcs_xstrdup(fname);
	char *ext = strrchr(base_name, '.');
	if (ext)
	{
		int i;
		for (i = 0; log_exts[i] != NULL; i++) {
			if (!strcmp(ext, log_exts[i])) {
				*ext = 0;
				if (pext) {
					*pext = log_exts[i];
				}
				return base_name;
			}
		}
	}
	if (pext) {
		*pext = "";
	}
	return base_name;
}

void pcs_apply_log_files_limits(int nfiles, unsigned long long total_size, abs_time_t age_sec)
{
	struct log_writer *l = logwriter;
	logrotate_apply_limits(l->rotate.basename, nfiles, total_size, age_sec);
}

#define LOG_FLUSH_TOUT 5

#if defined(__LINUX__) && __GLIBC_PREREQ(2, 4) && defined(_POSIX_MONOTONIC_CLOCK) && (_POSIX_MONOTONIC_CLOCK >= 0)
#define USE_MONOTONIC_CLOCK
#endif

static pcs_thread_ret_t log_worker(void* arg)
{
	int res = 0;
	struct log_writer* l = arg;
	pcs_thread_setname("logger");
	for (;;)
	{
		struct timespec ts;
#ifdef USE_MONOTONIC_CLOCK
		res = clock_gettime(CLOCK_MONOTONIC, &ts);
		BUG_ON(res);
#else
		struct timeval tv;
		gettimeofday(&tv, 0);
		ts.tv_sec = tv.tv_sec;
		ts.tv_nsec = tv.tv_usec * 1000;
#endif
		ts.tv_sec += LOG_FLUSH_TOUT;
		pthread_mutex_lock(&loglock);
		/* Sleeping loop */
		for (;;)
		{
			/* Check wake up conditions */
			if (l->b[0].full || l->b[1].full)
				break;
			if (l->rotate.request || l->close_request)
				break;

			res = pthread_cond_timedwait(&l->cond, &loglock, &ts);
			BUG_ON(res && res != ETIMEDOUT);
			if (res == ETIMEDOUT)
				break;
		}
		/* Flush buffer if necessary */
		if (l->b[l->curr].used && !l->b[l->curr].full)
		{
			int next_buff = LOG_BUFF_NEXT(l->curr);
			/* Enforce current buffer flushing on close or reopen or if the timeout is expired and
			 * we have the second buffer free (otherwise the client will block).
			 */
			if (l->rotate.request || l->close_request || (res == ETIMEDOUT && !l->b[next_buff].full)) {
				l->b[l->curr].full = l->b[l->curr].used;
				l->curr = next_buff;
				l->b[l->curr].used = 0;
			}
		}
		pthread_mutex_unlock(&loglock);

		if (!logrotate_maybe_run(&l->rotate, l->log_size)) {
			l->reopen_log(l);
			write_log_header(l);
		}

		/* Perform write if necessary */
		log_worker_write(l);

		/* Check need to terminate - but flush used buffers first */
		if (l->close_request && !l->b[l->curr].used && !l->b[l->curr].full)
		{
			l->close_log(l);
			break;
		}
	}
	return 0;
}

/*
 * The basic log API
 */

/* Fill provided buffer with buffered log tail or returns -1 if log is not buffered. */
int pcs_log_get_tail(char* buff, unsigned* sz)
{
	struct log_buff *curr, *prev;
	unsigned sz_curr, sz_left, sz_total = 0;
	if (!logwriter)
		return -1;

	pthread_mutex_lock(&loglock);
	/*
	 * Get the most we can from 2 buffers
	 */
	curr = &logwriter->b[logwriter->curr];

	if ((sz_curr = curr->used) <= (sz_left = *sz))
	{
		sz_left -= sz_curr;
		prev = &logwriter->b[LOG_BUFF_PREV(logwriter->curr)];
		if (prev->used <= sz_left)
		{
			memcpy(buff, prev->buff, prev->used);
			sz_total += prev->used;
		}
		else {
			memcpy(buff, prev->buff + prev->used - sz_left, sz_left);
			sz_total += sz_left;
		}
		memcpy(buff + sz_total, curr->buff, sz_curr);
		sz_total += sz_curr;
	}
	else {
		memcpy(buff, curr->buff + sz_curr - sz_left, sz_left);
		sz_total += sz_left;
	}

	pthread_mutex_unlock(&loglock);

	BUG_ON(sz_total > *sz);
	*sz = sz_total;
	return 0;
}

/* Prints the log message according to the following pattern:
 * [timestamp] [indentation] [prefix: ] message [\n]
 */
void pcs_valog(int level, const char *prefix, const char *fmt, va_list va)
{
	/* Trying to flush buffers after some fatal signal, don't mess around.
	 * This line is mainly necessary because gz_write_buff() calls
	 * pcs_log() in some conditions. */
	if (in_fatal_signal_handler)
		return;

	abs_time_t blocked_time = lock_log();

	if (blocked_time) {
		log_printf("[log blocked for %llums]\n", blocked_time);
	}

	log_vprintf_lvl(level | (log_nonl ? LOG_NOTS : 0), prefix, fmt, va);

	log_nonl = level & LOG_NONL;

	unlock_log();
}

int *pcs_log_lvl(void)
{
	return &__pcs_log_level;
}

int *pcs_log_indent(void)
{
	/* On Windows thread variable cannot be exported by dll
	 * See https://msdn.microsoft.com/en-us/library/40a45kxx.aspx */
	return &__log_indent;
}

static void pcs_valog_exitmsg(const char *fmt, va_list va);

void pcs_log(int level, const char *fmt, ...)
{
	va_list va;

	if ((level & LOG_LEVEL_MASK) > pcs_log_level)
		return;

	va_start(va, fmt);
	pcs_valog(level, NULL, fmt, va);
	va_end(va);
}

void pcs_trace(int level, const char* func, const char *fmt, ...)
{
	va_list va;

	if ((level & LOG_LEVEL_MASK) > pcs_log_level)
		return;

	va_start(va, fmt);
	pcs_valog(level, func, fmt, va);
	va_end(va);
}

void pcs_log_hexdump(int level, const void *buf, int olen)
{
	int len = olen > 64 ? 64 : olen;
	char *str = 0, *p = 0;
	int alloc_sz;
	int i;

	if ((level & LOG_LEVEL_MASK) > pcs_log_level)
		return;

	alloc_sz = len * 3 + 3 + 1;
	str = (char*)pcs_xmalloc(alloc_sz);
	p = str;

	*p = 0;
	for (i = 0; i < len; i++)
		p += sprintf(p, "%02x ", *((unsigned char *)buf + i));
	if (olen > len)
		p += sprintf(p, "...");
	BUG_ON(p > str + alloc_sz);
	str[alloc_sz - 1] = 0;

	pcs_log(level|LOG_NOIND, "%s", str);
	pcs_free(str);
}

void pcs_fatal(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	pcs_valog(LOG_ERR|LOG_NOIND, "Fatal", fmt, va);
	va_end(va);
	va_start(va, fmt);
	pcs_valog_exitmsg(fmt, va);
	va_end(va);
	if (pcs_log_level > LOG_WARN)
		show_trace();

	pcs_log_terminate();

	/* use same exit code as abort */
	exit(-134);
}

__noinline void show_trace(void)
{
	/* Trying to flush buffers after some fatal signal, don't mess around.
	 * This line is mainly necessary because gz_write_buff() calls
	 * pcs_log() in some conditions. */
	if (in_fatal_signal_handler)
		return;

	lock_log();
	trace_dump(NULL, log_printf);
	unlock_log();
}

void show_trace_coroutine(struct pcs_ucontext *ctx)
{
	lock_log();
	trace_dump_coroutine(ctx, log_printf);
	unlock_log();
}

void pcs_log_version_register(const char *version)
{
	if (version_nr >= VERSION_LIST_MAX)
		return;
	version_list[version_nr++] = version;
}

int pcs_log_get_registered_versions(const char *versions[], int sz)
{
	int i;

	if (version_nr < sz)
		sz = version_nr;
	for (i = 0; i < sz; i++)
		versions[i] = version_list[i];
	return sz;
}

/*
 * Initialize log ops depending on 'compression' extension.
 * It could be 'gz', 'zst' for corresponsing compression or some other,
 * in which case no compression will be used. If libpcs is compiled without
 * ZST compression and with gzip compression support, and ext is 'zst', then
 * it fallbacks to gzip compression.
 *
 * Returns file extension (it make sense in case of fallback to gzip).
 */
const char * init_ops(struct log_writer *l, const char *ext) {
	init_ops_generic(l);

	if (!ext)
		return "";

#ifdef _ENABLE_GZIP_COMPRESSION
	if (!strcmp(ext, "gz")) {
		init_ops_gzip(l);
		return ext;
	}
#endif
#if defined(_ENABLE_ZSTD_COMPRESSION) || defined(_ENABLE_GZIP_COMPRESSION)
	if (!strcmp(ext, "zst")) {
#ifdef _ENABLE_ZSTD_COMPRESSION
		init_ops_zstd(l);
		return ext;
#else
		init_ops_gzip(l);
		return "gz";
#endif
	}
#endif

	return ext;
}

int pcs_set_logfile_ex(const char *prefix, const char *compression, int flags)
{
	int res = 0;
	struct log_writer* l;
	const char *ext;
	int rotate_mode = flags & PCS_LOG_ROTATE_MASK;

	/* This function may be called only once. It is expected to be called at the application startup so
	 * no protection from concurrent log access.
	 */
	BUG_ON(logwriter);

	/* Only one of two functions: pcs_set_logfile() or pcs_set_log_handler() must be called. */
	BUG_ON(log_handler);

	if (rotate_mode != PCS_LOG_ROTATE_ENUM && rotate_mode != PCS_LOG_ROTATE_MULTIPROC)
		return PCS_ERR_INV_PARAMS;

	/* Allocate context */
	l = pcs_xzmalloc(sizeof(*l));

	l->lflags = flags;

	l->rotate.rflags = rotate_mode;
	l->rotate.basename = pcs_xstrdup(prefix);
	l->rotate.fname_p = &l->fname;
	/* First, init logger to rotate all existent logs on openning (FIXME) */
	l->rotate.filenum = MAX_LOG_ROTATE_FILENUM;

	ext = init_ops(l, compression);

	/* No buffer yet written */
	l->written = -1;
	l->lock_fd = PCS_INVALID_FD;

#ifdef __WINDOWS__
	l->rotate.id = GetCurrentProcessId();
#else
	l->rotate.id = getpid();
#endif

	if (rotate_mode == PCS_LOG_ROTATE_MULTIPROC) {
		if (strlen(ext) != 0) {
			res = snprintf(l->rotate.ext, sizeof(l->rotate.ext), ".log.%s", ext);
			BUG_ON(res > sizeof(l->rotate.ext) - 1);
		} else {
			strncpy(l->rotate.ext, ".log", sizeof(l->rotate.ext));
		}

		l->fname = format_filename_ts(prefix, l->rotate.ext, l->rotate.id);
	} else {
		BUG_ON(sizeof(l->rotate.ext) < strlen(ext) + 1);
		strncpy(l->rotate.ext, ext, sizeof(l->rotate.ext) - 1);
		l->rotate.ext[sizeof(l->rotate.ext) - 1] = '\0';

		l->fname = pcs_xasprintf("%s%s%s", prefix, (l->rotate.ext[0] != '\0') ? "." : "", l->rotate.ext);
	}

	/* Open log file */
	if (l->open_log(l)) {
		LOGGER_ERR("Can't initialize log subsystem.\n");
		pcs_free(l);
		return PCS_ERR_IO;
	}

	/* Init rotation default; could be changed by user later */
	l->rotate.filenum = DEF_LOG_ROTATE_FILENUM;

	/* Create condition to wait on */
	res = pthread_condattr_init(&l->condattr);
	BUG_ON(res);
#ifdef USE_MONOTONIC_CLOCK
	res = pthread_condattr_setclock(&l->condattr, CLOCK_MONOTONIC);
	BUG_ON(res);
#endif
	res = pthread_cond_init(&l->cond, &l->condattr);
	BUG_ON(res);

	/* Create worker thread */
	res = pcs_thread_create(&l->worker, NULL, log_worker, l);
	BUG_ON(res);

	/* Succeeded */
	logwriter = l;
	write_log_header(l);
	atexit(pcs_log_terminate);

	return 0;
}

int pcs_set_logfile(const char *path)
{
	char *basename;
	const char *ext;
	int rc;

	basename = get_basename_ext(path, &ext);
	if (strlen(ext) > 0)
		ext = ext + 1;
	rc = pcs_set_logfile_ex(basename, ext, PCS_LOG_ROTATE_ENUM);
	pcs_free(basename);

	return rc;
}

/* Returns currently used log file or NULL if it was not set yet */
const char* pcs_get_logfile(void)
{
	if (logwriter) {
		return logwriter->fname;
	} else {
		return 0;
	}
}

/* Returns currently used logfile path split onto the basename part and extension.
 * The returned basename part must be freed by caller passing them to pcs_free().
 */
char* pcs_get_logfile_base_ext(const char** pext)
{
	if (logwriter) {
		return get_basename_ext(logwriter->fname, pext);
	} else {
		if (pext) {
			*pext = 0;
		}
		return 0;
	}
}

void pcs_set_log_handler(void (*handler)(int level, int indent, const char *prefix, const char *fmt, va_list va))
{
	/* Only one of two functions: pcs_set_logfile() or pcs_set_log_handler() must be called. */
	BUG_ON(logwriter);

	/* This function may be called only once. It is expected to be called at the application startup so
	 * no protection from concurrent log access.
	 */
	BUG_ON(log_handler);

	log_handler = handler;
}

void pcs_log_terminate(void)
{
	struct log_writer* l = NULL;

	/* Trying to flush buffers after some fatal signal, don't mess around.
	 * This line is mainly necessary because gz_write_buff() calls
	 * pcs_log() in some conditions. */
	if (in_fatal_signal_handler)
		return;

	log_handler = NULL;

	if (!logwriter)
		return;

	pthread_mutex_lock(&loglock);
	if (log_writer_active()) {
		l = logwriter;
		logwriter->close_request = 1;
		pthread_cond_broadcast(&logwriter->cond);
#ifdef PCS_ADDR_SANIT
		__lsan_ignore_object(logwriter);
#endif
		logwriter = NULL;
	}
	pthread_mutex_unlock(&loglock);

	if (l) {
		pcs_thread_join(l->worker);
		if (l->lock_fd != PCS_INVALID_FD)
			pcs_sync_close_lock_file(l->fname, l->lock_fd);
	}
	/* Don't free any resources since we are terminating anyway */
}

/* Returns last incomplete buffer */
static struct log_buff * flush_full_buffers(void)
{
	int next_buff;
	struct log_buff *b;

	if (log_nonl) {
		log_printf("");
		log_nonl = 0;
	}

	if (!logwriter)
		return NULL;

	/* lock flushlock and loglock */
	if (pthread_mutex_trylock(&flushlock)) {
		if (pcs_thread_equal(logwriter->worker, pcs_thread_self()))
			/* fatal error in the logwriter during
			 * flushing the log, can't recover :( */
			abort();
		/* logwriter is flushing the log, let him finish the job */
		pthread_mutex_lock(&flushlock);
	}
	pthread_mutex_lock(&loglock);

	/* flush full buffers first */
	while (1) {
		next_buff = LOG_BUFF_NEXT(logwriter->written);
		b = &logwriter->b[next_buff];
		if (!b->full)
			break;
		logwriter->write_buff(logwriter, b);
		b->full = b->used = 0;
	}

	return b;
}

static void flush_log_buffer(struct log_buff *b)
{
	if (!b)
		return;

	BUG_ON(!logwriter);
	/* flush the rest */
	b->full = b->used;
	logwriter->write_buff(logwriter, b);
}

#ifndef __WINDOWS__
static void describe_signal(int sig, siginfo_t *info, void *pc)
{
	/* describe the signal */
	const char *sigstr = strsignal(sig);
	if (sigstr == NULL)
		sigstr = "";

	switch (sig) {
		case SIGILL:
		case SIGFPE:
		case SIGSEGV:
		case SIGBUS:
			log_printf("Got signal %d (%s) with code %d at %p, invalid address is %p", sig, sigstr, info->si_code, pc, info->si_addr);
			break;
		default:
			log_printf("Got signal %d (%s) with code %d", sig, sigstr, info->si_code);
	}
}

/* This signal handler expects that it is registered using sigaction() with
 * flags field set to SA_NODEFER | SA_RESETHAND | SA_SIGINFO.
 * Due to SA_RESETHAND the signal action is restored to the default upon
 * entry to the signal handler. Then returning from the handler makes
 * execution to be restarted from the faulty instruction which will do
 * another fault, so we'll get one more signal of the same type, but now the
 * default handler will be called.
 */
void pcs_log_fatal_sighandler(int sig, siginfo_t *info, void *context)
{
	if (in_fatal_signal_handler) {
		/* double fault, can't recover :( */
		/* SA_RESETHAND is ignored when called from Go signal handler, reseting handler explicitly */
		signal(sig, SIG_DFL);
		return;
	}
	in_fatal_signal_handler = 1;

#if defined(__linux__)
	/* add PROFILER_SIGNO in mask of blocked signals to avoid truncated coredumps */
	sigaddset(&((ucontext_t*)context)->uc_sigmask, PROFILER_SIGNO);
#endif

	struct log_buff *b = flush_full_buffers();

	describe_signal(sig, info, register_get_pc((ucontext_t*)context));
	register_dump((ucontext_t*)context, log_printf);
	trace_dump((ucontext_t*)context, log_printf);

	flush_log_buffer(b);

	/* re-raise signal, handler is reset due to SA_RESETHAND and leads to default handler (core) */
	raise(sig);
}
#else /* __WINDOWS__ */
LONG __stdcall pcs_log_fatal_sighandler(EXCEPTION_POINTERS *ptrs)
{
	LONG rc = EXCEPTION_CONTINUE_SEARCH;

	if (in_fatal_signal_handler || ptrs->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW) {
		if (old_fatal_handler)
			old_fatal_handler(ptrs);

		return rc;
	}
	in_fatal_signal_handler = 1;

	struct log_buff *b = flush_full_buffers();

	register_dump(ptrs, log_printf);
	trace_dump(ptrs, log_printf);

	flush_log_buffer(b);

	if (old_fatal_handler)
		old_fatal_handler(ptrs);

	return rc;
}
#endif /* __WINDOWS__ */

/*
 * Log rotation API
 */

void pcs_set_logrotate_size(unsigned long long size)
{
	TRACE("%llu", size);
	if (!log_writer_active())
		return;
	logwriter->rotate.threshold = size;
}

void pcs_set_logrotate_filenum(unsigned int filenum)
{
	TRACE("%u", filenum);
	if (!log_writer_active())
		return;
	if (filenum < 2)
		filenum = 2;
	if (filenum > MAX_LOG_ROTATE_FILENUM)
		filenum = MAX_LOG_ROTATE_FILENUM;
	logwriter->rotate.filenum = filenum;

	/* Remove greater-numbered logs
	   Rotation collection looks like [.gz, 0.gz, 1.gz,... {filenum - 2}.gz] -- totally filenum items */
	logrotate_unlink_unused(logwriter->rotate.basename, filenum - 1, MAX_LOG_ROTATE_FILENUM);
}

void pcs_ext_logrotate_force(void)
{
	/* We shouldn't call any logging functions here. loglock is recursive,
	 * but the problem is with the internal locking in localtime() */
	if (!log_writer_active())
		return;

	logwriter->rotate.request = 1;
	pthread_cond_broadcast(&logwriter->cond);
}

PCS_API void pcs_set_logrotate_limits(unsigned long long rotate_size, int nfiles, unsigned long long total_size, abs_time_t age_sec)
{
	TRACE("nfiles=%d, rotate_size=%llu, total_size=%llu, max_age=%llu", nfiles, rotate_size, total_size, age_sec);
	if (!log_writer_active())
		return;

	logwriter->rotate.max_nfiles = nfiles;
	logwriter->rotate.max_total_size = total_size;
	logwriter->rotate.max_age_sec = age_sec;
	logwriter->rotate.threshold = rotate_size;

	pcs_apply_log_files_limits(nfiles, total_size, age_sec);
}


/* Signal handler for external rotation requests.
 * Unlike built in log rotation routine the external one works by means of renaming log files already open
 * by our application and sending us the special signal to force reopening log file without changing its name.
 * Note that the signal received can stop us with any locks acquired so just set request flag here
 * and wake up worker without locking. Don't care about lost signal since the worker will be awakened on next
 * buffer write anyway.
 */
void pcs_ext_logrotate_sighandler(int signum)
{
	pcs_ext_logrotate_force();
}

/*
 * The exit message file implements the mechanism for application to report postmortem message to the monitoring tool.
 * So it is not directly related to the log itself.
 */

static char *log_exit_msg_fname;

void pcs_set_exitmsg_file(char *path)
{
	BUG_ON(log_exit_msg_fname);
	log_exit_msg_fname = pcs_strdup(path);
}

static void pcs_valog_exitmsg(const char *fmt, va_list va)
{
	int fd = 0;
	FILE *f;
	int ret;

	if (!log_exit_msg_fname)
		return;

	/* this is to make sure that file will not be truncated */
	if ((fd = log_file_open(log_exit_msg_fname, O_WRONLY | O_CREAT, 0600)) < 0) {
		pcs_log(LOG_ERR, "Failed to open exit message file: %s", strerror(errno));
		return;
	}

	f = fdopen(fd, "w");
	if (!f) {
		pcs_log(LOG_ERR, "Failed to open exit message file: %s", strerror(errno));
		log_file_close(fd);
		return;
	}

	ret = vfprintf(f, fmt, va);
	if ((ret < 0) || (fputc('\0', f) == EOF))
		pcs_log(LOG_ERR, "Failed to write exit message");

	if (fclose(f) == EOF)
		pcs_log(LOG_ERR, "Error while closing exit message file: %s", strerror(errno));
}

void pcs_log_exitmsg(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	pcs_valog_exitmsg(fmt, va);
	va_end(va);
}

static void init_ops_generic(struct log_writer* l)
{
	l->open_log =  __open_log_file;
	l->write_buff = __write_log_buff;
	l->close_log = __log_worker_close;
	l->reopen_log = __log_worker_reopen;
}

#if defined(_ENABLE_GZIP_COMPRESSION) || defined(_ENABLE_ZSTD_COMPRESSION)
static void z_close_log(struct log_writer *l)
{
	int res;
	if (z_funcs.file_is_null(l))
		return;

	res = z_funcs.close(l);
	log_file_close(l->fd);
	if (res != 0) {
#ifdef _ENABLE_GZIP_COMPRESSION
		if (res == Z_ERRNO)
			LOGGER_ERR("failed to close compressed log file %s: %s\n", l->fname, strerror(errno));
		else
#endif
			LOGGER_ERR("failed to close compressed log file %s: %d\n", l->fname, res);
	}

	l->fd = (pcs_fd_t )-1;
	BUG_ON(!z_funcs.file_is_null(l));
}

static int z_reopen_stream(struct log_writer* l)
{
	int fd = log_file_dup((int)l->fd);
	if (fd < 0) {
		LOGGER_ERR("failed to duplicate file descriptor %s\n", strerror(errno));
		z_close_log(l);
		return -1;
	}

	z_close_log(l);
	if (log_file_getsize(fd, (u64*)(&l->log_size)) < 0) {
		LOGGER_ERR("failed to get file size %s\n", strerror(errno));
		goto _err;
	}
	if (log_file_lseek(fd, 0, SEEK_END) < 0) {
		LOGGER_ERR("failed to seek to the end of file - %s\n", strerror(errno));
		goto _err;
	}

	if (z_funcs.dopen(l, fd) != 0) {
		LOGGER_ERR("failed to open zip stream\n");
		goto _err;
	}

	l->fd = (pcs_fd_t)fd;
	return 0;

_err:
	log_file_close(fd);
	return -1;
}

static int z_open_log_by_fd(struct log_writer *l, int fd)
{
	int err = 0;
	u64 size = 0;

	if ((err = log_file_getsize(fd, &size)) < 0) {
		LOGGER_ERR("failed to get file size - %s\n", strerror(errno));
		goto _end;
	}

	if ((err = log_file_lseek(fd, 0, SEEK_END)) < 0) {
		LOGGER_ERR("failed to seek to the end of file - %s\n", strerror(errno));
		goto _end;
	}

	if (z_funcs.dopen(l, fd) != 0) {
		LOGGER_ERR("failed to open zip stream\n");
		err = -1;
		goto _end;
	}

	l->fd = (pcs_fd_t)fd;
	l->log_size = size;
_end:
	return err;
}

static int z_truncate_existing_and_open(struct log_writer *log, int fd, u64 size)
{
	int err;
	LOGGER_ERR("truncate log at %llu\n", (unsigned long long)size);
	if ((err = log_file_ftruncate(fd, (u64)size)) < 0) {
		LOGGER_ERR("ftruncate failed - %s\n", strerror(errno));
		return err;
	}

	if ((err = z_open_log_by_fd(log, fd)) < 0) {
		LOGGER_ERR("failed to open log by fd\n");
		return err;
	}

	char str[128];
	snprintf(str, sizeof(str), "\n\n------ truncated log at %llu ------\n\n", (unsigned long long)size);
	z_funcs.puts(log, str);
	z_funcs.flush(log);

	return 0;
}

static int z_add_last_record(struct log_writer *log, unsigned char *buf, int buf_len)
{
	int err;
	u64 size = 0;
	char str[128];

	if (!buf_len)
		goto done;

	/* rewrite last chunk */
	snprintf(str, sizeof(str), "\n\n------ fixing last compressed log record (%d non-compressed bytes follow) ------\n\n", buf_len);
	err = z_funcs.puts(log, str);
	if (err <= 0) {
		const char *msg = z_funcs.get_error(log, &err);
		LOGGER_ERR("compressed puts failed - %s, %d\n", msg, err);
		return -1;
	}

	err = z_funcs.write(log, buf, buf_len);
	if (err <= 0) {
		const char *msg = z_funcs.get_error(log, &err);
		LOGGER_ERR("compressed write (%d bytes) failed - %s, %d\n", buf_len, msg, err);
		return -1;
	}

	if (z_funcs.flush(log) != 0) {
		LOGGER_ERR("Unable to flush zip stream\n");
		return -1;
	}

	if ((err = log_file_getsize(log->fd, &size)) < 0) {
		LOGGER_ERR("failed to get file size - %s\n", strerror(errno));
		return -1;
	}

	snprintf(str, sizeof(str), "\n\n------ end of restored compressed log record (file size at %llu). warning: log may be incomplete! ------\n\n", (unsigned long long)size);
	z_funcs.puts(log, str);
	if (z_funcs.flush(log) != 0) {
		LOGGER_ERR("Unable to flush zip stream\n");
		return -1;
	}

done:
	if ((err = log_file_getsize(log->fd, &size)) < 0) {
		LOGGER_ERR("failed to get file size - %s\n", strerror(errno));
		return -1;
	}
	log->log_size = size;
	return 0;
}

static int z_open_log(struct log_writer *l)
{
	int fd = 0;
	u64 size = 0;

	BUG_ON(!l->fname);
	if (log_fname_lock(l) < 0)
		return -1;

	fd = log_file_open(l->fname, O_RDWR, 0);
	if (fd < 0) {
		if (errno == ENOENT) {
			if (logrotate_run_alt(&l->rotate, l->fname) < 0)
					return -1;
			fd = log_file_open(l->fname, O_RDWR | O_CREAT, 0666);
		}

		if (fd < 0) {
			LOGGER_ERR("failed to open log file %s : %s\n", l->fname, strerror(errno));
			return -1;
		}

		if (z_open_log_by_fd(l, fd) < 0) {
			log_file_close(fd);
			LOGGER_ERR("failed to open log file by fd\n");
			return -1;
		}
	} else {
		if (log_file_getsize(fd, &size) < 0) {
			LOGGER_ERR("can't stat file %s - %s\n", l->fname, strerror(errno));
			log_file_close(fd);
			return -1;
		}
		return z_funcs.open_existing(fd, size, l);
	}

	return 0;
}

static void z_write_buff(struct log_writer* l, struct log_buff* b)
{
	int size = b->full;
	char *ptr = b->buff;
	BUG_ON(!size);
	BUG_ON(size > LOG_BUFF_SZ);

	if (z_funcs.file_is_null(l)) {
		if (z_open_log(l) < 0)
			return;
	}

	while (size > 0) {
		int rc = z_funcs.write(l, ptr, size);
		if (!rc) {
			int err;
			const char *errmsg;
			errmsg = z_funcs.get_error(l, &err);
			LOGGER_ERR("z_write failed - %d, %s\n", err, errmsg);
			z_funcs.clear_err(l);
			return;
		}

		BUG_ON(rc < 0);

		ptr += rc;
		size -= rc;
	}

	(void)z_reopen_stream(l);
}

static int z_reopen_log(struct log_writer* l)
{
	int fd = 0;

	z_close_log(l);
	BUG_ON(l->lock_fd == PCS_INVALID_FD);
	fd = log_file_open(l->fname, O_RDWR|O_CREAT, 0666);
	if (fd < 0) {
		LOGGER_ERR("Unable open file %s - %s\n", l->fname, strerror(errno));
		return -1;
	}

	if (z_funcs.dopen(l, fd) != 0) {
		LOGGER_ERR("z_dopen failed\n");
		log_file_close(fd);
		return -1;
	}

	l->fd = (pcs_fd_t)fd;
	l->log_size = 0;
	return 0;
}
#endif /* defined(_ENABLE_GZIP_COMPRESSION) || defined(_ENABLE_ZSTD_COMPRESSION) */

#ifdef _ENABLE_GZIP_COMPRESSION
static int gz_dopen(struct log_writer *l, pcs_fd_t fd)
{
	int gz_fd = log_file_dup(fd);
	if (gz_fd < 0)
		return -1;
	l->gz_file = gzdopen(gz_fd, GZIP_COMPRESSION_LEVEL);
	return l->gz_file ? 0 : -1;
}

/* this closes gz_file with gzclose and inherent fd */
static int gz_close(struct log_writer *l)
{
	int res = gzclose(l->gz_file);
	l->gz_file = NULL;
	return (res == Z_OK) ? 0 : res;
}

static int gz_file_is_null(struct log_writer* l)
{
	return !(l->gz_file);
}

static int gz_write(struct log_writer *l, const void *buff, int len)
{
	return gzwrite(l->gz_file, buff, len);
}

static const char *gz_error(struct log_writer *l, int *errnum)
{
	return gzerror(l->gz_file, errnum);
}

static int gz_puts(struct log_writer *l, char *str)
{
	return gzputs(l->gz_file, str);
}

static void gz_clearerr(struct log_writer *l)
{
	gzclearerr(l->gz_file);
}

static int gz_flush(struct log_writer *l)
{
	int res = gzflush(l->gz_file, Z_FINISH);
	return (res == Z_OK) ? 0 : res;
}

#define HDR_FLAGS       0
#define HDR_XFLAGS      0
#if defined(__WINDOWS__)
#define HDR_OSCODE      11
#elif defined(__MAC__)
#define HDR_OSCODE      19
#else
#define HDR_OSCODE      3
#endif
#define HDR_OSCODE_MASK 0x1f
#define GZ_FOOTER_LEN  8

static const unsigned char gz_hdr_signature[10] =
	{ 0x1f, 0x8b, Z_DEFLATED, HDR_FLAGS, 0, 0, 0, 0, HDR_XFLAGS, 0 /* OSCODE is masked as variable */};

static const unsigned char gz_hdr_mask[10] =
	{ 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, ~HDR_OSCODE_MASK };

struct gz_footer {
	u32 crc32;
	u32 isize;
};

static int gz_seek_last_record(int fd, u64 size, u64 *poffs, struct gz_footer *footer)
{
	unsigned char *header = NULL, *ptr;
	unsigned int *magic = (unsigned int*)gz_hdr_signature;
	unsigned char *buf;
	int buf_len;
	u64 offs;
	int err = -1;

	buf = pcs_xmalloc(LOG_BUFF_SZ);

	offs = (size > LOG_BUFF_SZ) ? size - LOG_BUFF_SZ : 0;

	/* read last LOG_BUFF_SZ of log */
	if (log_file_lseek(fd, offs, SEEK_SET) < 0) {
		LOGGER_ERR("failed to seek - %s\n", strerror(errno));
		goto err;
	}

	buf_len = log_file_read(fd, buf, LOG_BUFF_SZ);
	if (buf_len < 0) {
		LOGGER_ERR("can't read tail of log - %s\n", strerror(errno));
		err = -2;
		goto err;
	}

	/* try find gzip header in log's tail */
	for (ptr = (buf + buf_len) - sizeof(gz_hdr_signature); ptr >= buf; ptr--) {
		unsigned int i, *val = (unsigned int *)ptr;
		if (*val != *magic)
			continue;

		/* validate full header */
		for(i=0; i<sizeof(gz_hdr_signature); ++i) {
			if ((ptr[i] & gz_hdr_mask[i]) != gz_hdr_signature[i])
				break;
		}

		if (i < sizeof(gz_hdr_signature))
			continue;

		header = ptr;
		break;
	}

	if (!header) {
		LOGGER_ERR("Unable to find gzip header in log's tail\n");
		err = -3;
		goto err;
	}

	offs = offs + (header - buf);
	BUG_ON(offs > size);
	s64 out_offs = log_file_lseek(fd, offs, SEEK_SET);
	if (out_offs < 0 || (u64)out_offs != offs) {
		LOGGER_ERR("lseek failed - %s\n", strerror(errno));
		err = -4;
		goto err;
	}

	BUG_ON(sizeof(*footer) != GZ_FOOTER_LEN);
	BUG_ON(buf_len < sizeof(gz_hdr_signature) + GZ_FOOTER_LEN);
	memcpy(footer, buf + buf_len - GZ_FOOTER_LEN, GZ_FOOTER_LEN);

	*poffs = offs;
	err = 0;

err:
	pcs_free(buf);
	return err;
}

static int gz_read_last_record(int fd, unsigned char **pbuf, int *pbuf_len, struct gz_footer *footer)
{
	gzFile f;
	*pbuf = NULL;
	*pbuf_len = 0;

	fd = log_file_dup(fd);	/* after successful gzdopen() fd belongs to f */
	if (fd < 0) {
		LOGGER_ERR("failed to duplicate file descriptor %s\n", strerror(errno));
		return -1;
	}

	/* try decompress last chunk */
	f = gzdopen(fd, "r");
	if (!f) {
		log_file_close(fd);
		LOGGER_ERR("failed to open log file for read\n");
		return -2;
	}

	int max_len = 2 * LOG_BUFF_SZ, len = 0, err = 0;
	unsigned char *buf = pcs_xmalloc(max_len);

	while (len < max_len && (err = gzread(f, buf + len, max_len - len)) > 0) {
		len += err;
	}

	int eof = gzeof(f);	/* should not access gzeof() after gzclose() ! */
	gzclose(f); /* this closes fd itself */

	if (err > 0) {		/* this should not normally happen, means that record is bigger then expected... let rotate the log then... */
		pcs_free(buf);
		return -3;
	}

	if (!err && eof && (u32)len == footer->isize && crc32(0, buf, len) == footer->crc32) {
		/* successfully decompressed last record AND it has correct footer/CRC */
		pcs_free(buf);
		return 1;
	}
	LOGGER_ERR("REC err %d, eof %d, len %d/%u, crc %x/%x\n", err, eof, len, footer->isize, (unsigned int)crc32(0, buf, len), (unsigned int)footer->crc32);

	*pbuf = buf;
	*pbuf_len = len;
	return 0;
}

/* unlike other functions open_existing() closes fd on errors, i.e. caller should forget about fd at all */
static int gz_open_existing(int fd, u64 size, struct log_writer *log)
{
	struct gz_footer footer;
	int buf_len, err;
	unsigned char *buf = NULL;
	u64 offs;
	int reason;

	if (size <= (GZ_FOOTER_LEN + sizeof(gz_hdr_signature))) {
		err = z_truncate_existing_and_open(log, fd, 0);
		if (err)
			log_file_close(fd);
		return err;
	}

	reason = 1;
	err = gz_seek_last_record(fd, size, &offs, &footer);
	if (err)
		goto rotate;

	reason = 2;
	err = gz_read_last_record(fd, &buf, &buf_len, &footer);
	if (err < 0)
		goto rotate;
	reason = 3;
	if (err > 0) {		/* file is not corrupted */
		if (z_open_log_by_fd(log, fd) < 0)
			goto rotate;
		return 0;
	}

	/* last file record is corrupted, truncate and rewrite */
	reason = 4;
	if (z_truncate_existing_and_open(log, fd, offs))
		goto rotate;

	reason = 5;
	err = z_add_last_record(log, buf, buf_len);
	if (err) {
		z_close_log(log);
		goto rotate;
	}

	pcs_free(buf);
	return 0;

rotate:
	pcs_free(buf);
	log_file_close(fd);

	if (logrotate_run(&log->rotate))
		return -1;
	log->reopen_log(log);

	if (!z_funcs.file_is_null(log)) {
		char str[128];
		snprintf(str, sizeof(str), "------ gzlog file forcefully rotated on error (reason %d, err %d) ------\n\n", reason, err);
		gzputs(log->gz_file, str);
		gzflush(log->gz_file, Z_FINISH);
	}

	return z_funcs.file_is_null(log);
}

static void init_ops_gzip(struct log_writer* l)
{
	l->fd = (pcs_fd_t)-1;
	l->gz_file = NULL;

	l->open_log = z_open_log;
	l->write_buff = z_write_buff;
	l->close_log = z_close_log;
	l->reopen_log = z_reopen_log;

	z_funcs.open_existing = gz_open_existing;
	z_funcs.file_is_null = gz_file_is_null;
	z_funcs.dopen = gz_dopen;
	z_funcs.close = gz_close;
	z_funcs.write = gz_write;
	z_funcs.get_error = gz_error;
	z_funcs.puts = gz_puts;
	z_funcs.clear_err = gz_clearerr;
	z_funcs.flush = gz_flush;
}

#endif /* _ENABLE_GZIP_COMPRESSION */

#ifdef _ENABLE_ZSTD_COMPRESSION
static s32 file_write(int fd, const void* buff, u32 count)
{
#ifdef __WINDOWS__
	return (s32)_write(fd, buff, count);
#else /* __WINDOWS__ */
	return (s32)write(fd, buff, count);
#endif /* __WINDOWS__ */
}

static int write_data(pcs_fd_t fd, const char *buff, int sz)
{
	while (sz) {
		int n = file_write(fd, buff, sz);
		if (n < 0) {
			return -1;
		}
		BUG_ON(n == 0);
		buff += n;
		sz -= n;
	}

	return 0;
}

static void zst_clearerr(struct log_writer *l)
{
	l->zst.msg[0] = '\0';
}

static int zst_flush(struct log_writer *l)
{
	return 0; /* everything already flushed */
}

static int zst_dopen(struct log_writer *l, pcs_fd_t fd)
{
	zst_clearerr(l);
	return 0;
}

/* as ZSTD doesn't need special structure, don't need to close */
static int zst_close(struct log_writer *l)
{
	return 0;
}

static int zst_file_is_null(struct log_writer* l)
{
	return (l->fd == (pcs_fd_t )-1);
}

static int zst_write(struct log_writer *l, const void *buff, int len)
{
	void *compress_buff = l->zst.compress_buff;
	int compress_buff_size = l->zst.compress_buff_size;

	size_t const compressed_size = ZSTD_compress(compress_buff, compress_buff_size,
		buff, len, ZSTD_COMPRESSION_LEVEL);

	if (unlikely(ZSTD_isError(compressed_size))) {
		snprintf(l->zst.msg, ZSTD_ERR_MSG_MAX,
			"ZSTD_compress : %s \n", ZSTD_getErrorName(compressed_size));
		return 0;
	}

	int res = write_data(l->fd, compress_buff, compressed_size);
	if (unlikely(res != 0)) {
		snprintf(l->zst.msg, ZSTD_ERR_MSG_MAX,
			"write %d bytes failed\n", (int)compressed_size);
		return 0;
	}

	return len;
}

static const char *zst_error(struct log_writer *l, int *errnum)
{
	*errnum = -1; /* set -1 just for definiteness as this function usually being called after error detection */
	return l->zst.msg;
}

static int zst_puts(struct log_writer *l, char *str)
{
	return zst_write(l, str, strlen(str));
}

/*
| `Magic_Number` | `Frame_Header` |`Data_Block`| [More data blocks] | [`Content_Checksum`] |
|:--------------:|:--------------:|:----------:| ------------------ |:--------------------:|
| 4 bytes        |  2-14 bytes    | n bytes    |                    |   0-4 bytes          |
*/
static const unsigned char zst_hdr_signature[4] = {0x28, 0xB5, 0x2F, 0xFD};
static const unsigned zst_hdr_frame_header_min_size = 1;

static int zst_last_frame(int fd, u64 size, unsigned char **pbuf, int *pframe_len, u64 *pframe_offset, u64 *poffs)
{
	unsigned char *header = NULL, *ptr;
	unsigned int *magic = (unsigned int*)zst_hdr_signature;

	unsigned char* buf_ = pcs_xmalloc(LOG_BUFF_SZ);

	u64 offs = (size > LOG_BUFF_SZ) ? size - LOG_BUFF_SZ : 0;

	/* read last LOG_BUFF_SZ of log */
	if (log_file_lseek(fd, offs, SEEK_SET) < 0) {
		LOGGER_ERR("failed to seek - %s\n", strerror(errno));
		goto err;
	}

	int buf_len = log_file_read(fd, buf_, LOG_BUFF_SZ);
	if (buf_len < 0) {
		LOGGER_ERR("can't read tail of log - %s\n", strerror(errno));
		goto err;
	}

	/* try find zstd header in log's tail */
	for (ptr = (buf_ + buf_len) - sizeof(zst_hdr_signature); ptr >= buf_; ptr--) {
		unsigned int i, *val = (unsigned int *)ptr;
		if (*val != *magic) {
			continue;
		}

		/* validate full header */
		for(i=0; i < sizeof(zst_hdr_signature); ++i) {
			if (ptr[i] != zst_hdr_signature[i]) {
				break;
			}
		}

		if (i < sizeof(zst_hdr_signature)) {
			continue;
		}

		header = ptr;
		break;
	}

	if (!header) {
		LOGGER_ERR("Unable find zstd header in log's tail\n");
		goto err;
	}

	offs = offs + (header - buf_);

	*pbuf = buf_;
	*pframe_offset = header - buf_;
	*pframe_len = buf_len - *pframe_offset;
	*poffs = offs;
	return 0;

err:
	pcs_free(buf_);
	*pbuf = NULL;
	*pframe_len = 0;
	*pframe_offset = 0;
	*poffs = 0;
	return -1;
}

static int zst_decode_last_record(const unsigned char *frame, int frame_len, unsigned char **data, int *data_size)
{
	/* should use streaming api as we don't know real data size if they are corrupted */
	void* data_ = NULL;
	*data = NULL;
	*data_size = 0;

	u64 data_size_ = ZSTD_getDecompressedSize(frame, frame_len);
	if (data_size_ == 0)
		goto err;

	data_ = pcs_xmalloc(data_size_);

	ZSTD_DStream* const dstream = ZSTD_createDStream();
	if (dstream == NULL)
		goto err;

	size_t res = ZSTD_initDStream(dstream);
	if (ZSTD_isError(res))
		goto err;

	unsigned decompressed_size = 0;
	ZSTD_inBuffer input = {.src = frame, .size = frame_len, .pos = 0};
	while (input.pos < input.size) {
		ZSTD_outBuffer output = {.dst = data_, .size = data_size_, .pos = 0};
		size_t readed = ZSTD_decompressStream(dstream, &output , &input);
		decompressed_size = output.pos;
		if (ZSTD_isError(readed)) {
			/* it also could be corrupted frame */
			break;
		}
	}
	ZSTD_freeDStream(dstream);

	if (decompressed_size == data_size_) {
		/* successfully decompressed last record AND it has correct length */
		pcs_free(data_);
		return 1;
	}
	LOGGER_ERR("REC len %d/%d\n", (unsigned)decompressed_size, (unsigned)data_size_);

	*data = (unsigned char *)data_;
	*data_size = (unsigned)decompressed_size;
	return 0;

err:
	pcs_free(data_);
	return -1;
}

static int zst_open_existing(int fd, u64 size, struct log_writer *log)
{
	int frame_len, data_size, err;
	unsigned char *buf = NULL, *data = NULL;
	u64 frame_offset, offset;
	int reason;

	if (size <= (sizeof(zst_hdr_signature) + zst_hdr_frame_header_min_size)) {
		err = z_truncate_existing_and_open(log, fd, 0);
		if (err)
			log_file_close(fd);
		return err;
	}

	reason = 1;
	err = zst_last_frame(fd, size, &buf, &frame_len, &frame_offset, &offset);
	if (err)
		goto rotate;

	reason = 2;
	err = zst_decode_last_record(buf + frame_offset, frame_len, &data, &data_size);
	if (err < 0)
		goto rotate;

	reason = 3;
	if (err > 0) {	/* file is not corrupted */
		if (z_open_log_by_fd(log, fd) < 0)
			goto rotate;
		goto done;
	}

	/* last file record is corrupted, truncate and rewrite */
	reason = 4;
	if (z_truncate_existing_and_open(log, fd, offset))
		goto rotate;

	reason = 5;
	err = z_add_last_record(log, data, data_size);
	if (err)
		goto err_last_record;

done:
	pcs_free(data);
	pcs_free(buf);

	return 0;

err_last_record:
	z_close_log(log);
rotate:
	pcs_free(data);
	pcs_free(buf);

	log_file_close(fd);
	if (logrotate_run(&log->rotate)) {
		return -1;
	}
	log->reopen_log(log);

	if (!z_funcs.file_is_null(log)) {
		char str[128];
		snprintf(str, sizeof(str), "------ zstdlog file forcefully rotated on error (reason %d) ------\n\n", reason);
		zst_puts(log, str);
	}

	return z_funcs.file_is_null(log);
}

static int zst_magic_test(void)
{
	int ret;
	unsigned char data = 0;
	unsigned data_size = sizeof(data);

	const size_t cbound = ZSTD_compressBound(data_size);
	void* cdata = pcs_malloc(cbound);

	const size_t csize = ZSTD_compress(cdata, cbound, &data, data_size, ZSTD_COMPRESSION_LEVEL);
	BUG_ON(ZSTD_isError(csize));

	ret = memcmp(zst_hdr_signature, cdata, sizeof(zst_hdr_signature));
	pcs_free(cdata);

	return ret;
}


static void init_ops_zstd(struct log_writer* l)
{
	BUG_ON(zst_magic_test() != 0);

	l->fd = (pcs_fd_t)-1;

	l->zst.msg[0] = '\0';
	l->zst.compress_buff_size = ZSTD_compressBound(LOG_BUFF_SZ);
	l->zst.compress_buff = pcs_xmalloc(l->zst.compress_buff_size);

	l->open_log = z_open_log;
	l->write_buff = z_write_buff;
	l->close_log = z_close_log;
	l->reopen_log = z_reopen_log;

	z_funcs.open_existing = zst_open_existing;
	z_funcs.file_is_null = zst_file_is_null;
	z_funcs.dopen = zst_dopen;
	z_funcs.close = zst_close;
	z_funcs.write = zst_write;
	z_funcs.get_error = zst_error;
	z_funcs.puts = zst_puts;
	z_funcs.clear_err = zst_clearerr;
	z_funcs.flush = zst_flush;
}
#endif /* _ENABLE_ZSTD_COMPRESSION */

#endif /* PCS_LOG_ENABLED */

void pcs_err(const char *msg, const char *file, int line, const char *func)
{
	pcs_log(LOG_ERR | LOG_NOIND, "%s at %s:%d/%s()", msg, file, line, func);
#ifdef DEBUG
#define VER_DEBUG " (Debug)"
#else
#define VER_DEBUG ""
#endif
#ifdef __PCS_BUILD_VERSION
#define VER_BUILD " build version: " __xstr(__PCS_BUILD_VERSION)
#else
#define VER_BUILD " build version: N/A"
#endif

	pcs_log(LOG_ERR | LOG_NOIND, VER_BUILD VER_DEBUG);
	int i;
	for (i = 0; i < version_nr; i++)
		pcs_log(LOG_ERR | LOG_NOIND, " %s", version_list[i]);
	show_trace();
	pcs_abort();
}

static void write_log_header(struct log_writer *l) {
	struct log_buff *b = pcs_xzmalloc(sizeof(*b));
	const time_t now = time(0);
	char tz[6];
#ifndef __WINDOWS__
	struct tm tm, *tm_ret;
	int res;

	tm_ret = localtime_r(&now, &tm);
	BUG_ON(!tm_ret);
	res = strftime(tz, sizeof(tz), "%z", &tm);
	BUG_ON(!res);
#else
	// On Windows %z can return empty string, see
	// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strftime-wcsftime-strftime-l-wcsftime-l
	struct tm local, utc;
	localtime_s(&local, &now);
	gmtime_s(&utc, &now);

	// Following code will find difference between local and UTC hours as
	// numbers, so they must be in the same daylight saving mode
	utc.tm_isdst = local.tm_isdst;

	const time_t d = (mktime(&local) - mktime(&utc)) / 60; // time difference in minutes
	const time_t m = llabs(d) % 60;
	const time_t h = d / 60;
	snprintf(tz, sizeof(tz), "%+03d%02d", (int)h, (int)m);
#endif

	b->used = snprintf(b->buff, LOG_BUFF_SZ, "# Log session started. TZ=%s. Version=%s\n", tz, VER_BUILD VER_DEBUG);
	b->full = b->used;

	pthread_mutex_lock(&flushlock);
	l->write_buff(l, b);
	pthread_mutex_unlock(&flushlock);
	pcs_free(b);
}
