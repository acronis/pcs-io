/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCSLOGROTATE_H__
#define __PCSLOGROTATE_H__

/* Rotate scheme based on enumeration. The same as in logrotate. */
#define PCS_LOG_ROTATE_ENUM		0x0
/* Naming scheme which includes timestamps. Log files' names are
 * <prefix>-<start ts>.<pid>.log[.gz|.zst].
 *
 * NOTE: libpcs doesn't remove old log files in this mode. */
#define PCS_LOG_ROTATE_MULTIPROC	0x1

/*
 * Log rotation support (buffered writing only).
 */
#define DEF_LOG_ROTATE_FILENUM 5
#define MAX_LOG_ROTATE_FILENUM 100

struct logrotate {
	int             rflags; 
	char*		basename;

	/* Extension. For text logs, if compact timestamps are not used it can be
	 * .log, .gz and .zst, otherwise - .log, .log.gz and .log.zst. For blogs
	 * The extension must always be .blog.
	 */
	char		ext[9];

	/* If mode is TS, then the filename itself is changed, existing log files
	 * are kept intact */
	char**		fname_p;
	/* limits for multiproc rotation mode */
	int		max_nfiles;
	unsigned long long max_age_sec;
	long long	max_total_size;
	unsigned long	id;

	unsigned	filenum;
	int		request;
	long long	threshold;
};

int logrotate_unlink_unused(const char* base_name, int min_part_idx, int max_part_idx);
void logrotate_apply_limits(char *basename, int nfiles, unsigned long long total_size, abs_time_t age_sec);
int logrotate_run(struct logrotate *l);

/*
 * Checks whether current log file should be rotated and run
 * logrotate_run() if so. Returns 1 if rotation skipped, 0 if
 * it went OK and <0 on any error.
 */
int logrotate_maybe_run(struct logrotate *l, long long size);

/*
 * Checks whether log files with different exts are present
 * and runs logrotate_run() if so. Returns 1 if rotation skipped,
 * 0 if it went OK and <0 on any error.
 */
int logrotate_run_alt(struct logrotate *l, const char *fname);

#endif
