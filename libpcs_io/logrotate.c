/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

/*
 * The module implements logrotation functionality for both
 * textual and binary logging.
 */

#include "pcs_types.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#ifdef __WINDOWS__
#else
#include <unistd.h>
#endif

#include "pcs_config.h"
#include "pcs_malloc.h"
#include "pcs_sync_io.h"
#include "pcs_dir.h"
#include "bug.h"
#include "timer.h"
#include "log.h"
#include "logrotate.h"

struct log_dirent {
	struct cd_list list;
	char *name;
	abs_time_t mtime_ns;
	u64 size;
};

static int err_not_exists(int err) {
#ifdef __WINDOWS__
	return err == -ERROR_FILE_NOT_FOUND;
#else  /* __WINDOWS__ */
	return err == -ENOENT;
#endif /* __WINDOWS__ */
}

static int rename_pedantic(const char* src, const char* dst)
{
	int res = 0;
	if (((res = pcs_sync_rename(src, dst)) < 0) && !err_not_exists(res)) {
		char buf[256];
		pcs_sys_strerror_r(-res, buf, sizeof(buf));
		pcs_log(LOG_ERR, "failed to rename log file %s -> %s : %d (%s)", src, dst, -res, buf);
		return -1;
	}
	return 0;
}

static int rotate_file(const char* base_name, int part_idx, const char* ext)
{
	int rc = 0;
	char* part_name_next = pcs_xasprintf("%s.%d%s", base_name, part_idx + 1, ext);
	char* part_name;
	if (part_idx < 0) {
		part_name = pcs_xasprintf("%s%s", base_name, ext);
		rc |= rename_pedantic(part_name, part_name_next);
	} else {
		part_name = pcs_xasprintf("%s.%d%s", base_name, part_idx, ext);
		rc |= rename_pedantic(part_name, part_name_next);
		pcs_free(part_name);
		pcs_free(part_name_next);

		/* legacy */
		part_name = pcs_xasprintf("%s%s.%d", base_name, ext, part_idx);
		part_name_next = pcs_xasprintf("%s%s.%d", base_name, ext, part_idx + 1);
		rc |= rename_pedantic(part_name, part_name_next);
	}
	pcs_free(part_name);
	pcs_free(part_name_next);

	return rc;
}

static int file_exists(const char *pathname)
{
#ifdef __WINDOWS__
	WCHAR * w_pathname = pcs_utf8_to_utf16(pathname, -1);
	if (!w_pathname)
		return -(int)GetLastError();
	DWORD dwAttrib = GetFileAttributesW(w_pathname);
	pcs_free(w_pathname);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		 !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
#else /* __WINDOWS__ */
	return (access(pathname, 0) == 0) ? 1 : 0;
#endif /* __WINDOWS__ */
}

int logrotate_unlink_unused(const char* base_name, int min_part_idx, int max_part_idx)
{
	int rc = 0;
	int ext_idx, part_idx;
	char* part_name;

	if (min_part_idx < 0)
		min_part_idx = 0;
	for (part_idx = min_part_idx; part_idx <= max_part_idx; part_idx++)
		for (ext_idx = 0; log_exts[ext_idx] != NULL; ext_idx++) {
			part_name = pcs_xasprintf("%s.%d%s", base_name, part_idx, log_exts[ext_idx]);
			if (file_exists(part_name))
				rc |= pcs_sync_unlink(part_name);
			pcs_free(part_name);

			part_name = pcs_xasprintf("%s%s.%d", base_name, log_exts[ext_idx], part_idx);
			if (file_exists(part_name))
				rc |= pcs_sync_unlink(part_name);
			pcs_free(part_name);
		}

	return rc;
}

static int log_worker_rotate_enum(struct logrotate* l)
{
	int rc = 0;
	int ext_idx, part_idx;
	/*
	 * We used to supported some other naming approach in the past (.gz.0 e.g.)
	 * Example (wy whe have to logrotate_unlink_unused now):
	 * Let rotation_filenum = 3; i.e. we will have .gz, 0.gz and 1.gz for actual logs;
	 * Previosly we launched program with rotation_filenum = 2 and old-naming approach; i.e. we already have [.gz, .gz.0]
	 * 1 rotation: [.gz, gz.0]       --> [.gz, 0.gz, gz.1]           i.e. { .gz -> .0.gz, .gz.0 -> .gz.1 }
	 * 2 rotation: [.gz, 0.gz, gz.1] --> [.gz, .0.gz, .1.gz, gz.1]   i.e. { .gz -> .0.gz, .0.gz -> .1.gz }
	 * So, we should remove useles .gz.1 -- (rotation_filenum=3)-2 = 1
	 */
	if (logrotate_unlink_unused(l->basename, l->filenum - 2, l->filenum - 1))
		return rc;

	for (ext_idx = 0; log_exts[ext_idx] != NULL; ext_idx++) {
		/*
		 * rotate_file overrites .idx+1* with .idx* file;
		 * [.gz, 0.gz, 1.gz, .. (filenum-2).gz] -- totally filenum files,
		 * should do renaming from (filenum-3).gz file downto -1 matches no-indexed .gz file
		 */
		for (part_idx = l->filenum - 3; part_idx >= -1; --part_idx) {
			if (rotate_file(l->basename, part_idx, log_exts[ext_idx]))
				return rc;
		}
	}

	return rc;
}

static void remove_log_file(const char *dname, const char *fname) {
	char *path;
	int ret;

	path = pcs_xasprintf("%s%c%s", dname, PCS_PATH_SEP, fname);
	pcs_log(LOG_INFO, "Remove log file '%s'", path);
	if ((ret = pcs_sync_unlink(path)) < 0) {
		pcs_log(LOG_ERR, "Error deleting log file '%s': %d", path, ret);
	}
	pcs_free(path);
}

static void do_apply_log_files_limits(const char *dname, struct cd_list *h,
				int max_nfiles, unsigned long long max_total_size, abs_time_t max_age_sec)
{
	struct log_dirent *ldir, *tmp;
	int nfiles = 0;
	unsigned long long total_size = 0;
	abs_time_t cur_time_us = get_real_time_us();

	cd_list_for_each_entry_reverse_safe(struct log_dirent, ldir, tmp, h, list) {
		if (max_nfiles && nfiles + 1 > max_nfiles) {
			remove_log_file(dname, ldir->name);
			cd_list_del(&ldir->list);
			pcs_free(ldir);
			continue;
		}

		if (max_total_size && total_size + ldir->size > max_total_size) {
			remove_log_file(dname, ldir->name);
			cd_list_del(&ldir->list);
			pcs_free(ldir);
			continue;
		}

		if (max_age_sec && ldir->mtime_ns / 1000 < cur_time_us - max_age_sec * 1000000) {
			remove_log_file(dname, ldir->name);
			cd_list_del(&ldir->list);
			pcs_free(ldir);
			continue;
		}

		nfiles++;
		total_size += ldir->size;
	}
}

/* Split path on filesystem 'path' into directory name and file name.
 * 'path' may be modified. */
static void parse_file_path(char *path, char **dname, char **fname)
{
	*fname = strrchr(path, PCS_PATH_SEP);
	if (*fname) {
		**fname = '\0';
		(*fname)++;
		*dname = *path ? path : "/";
	} else {
		*fname = path;
		*dname = ".";
	}
}

int log_dirent_cmp(struct cd_list *a, struct cd_list *b)
{
	struct log_dirent *dira, *dirb;

	dira = cd_list_entry(a, struct log_dirent, list);
	dirb = cd_list_entry(b, struct log_dirent, list);

	return strcmp(dira->name, dirb->name);
}

void logrotate_apply_limits(char *basename, int nfiles, unsigned long long total_size, abs_time_t age_sec)
{
	char *base_copy = pcs_xstrdup(basename);
	char *dname = NULL;
	char *fname = NULL;
	pcs_dirent_t *dir;
	struct log_dirent *ldir, *ldir_tmp;
	int rc = -EINVAL;
	CD_LIST_HEAD(h);

	parse_file_path(base_copy, &dname, &fname);

	rc = pcs_dirent_first(dname, PCS_DIRENT_STAT, &dir);
	if (rc < 0) {
		pcs_log(LOG_ERR, "Error listing directory '%s': %d", dname, rc);
		goto out;
	}

	for (; rc > 0; rc = pcs_dirent_next(dir)) {
		if ((dir->stat.mode & S_IFMT) != S_IFREG)
			continue;
		if (strncmp(fname, dir->name, strlen(fname)))
			continue;

		ldir = pcs_xmalloc(sizeof(*ldir));
		ldir->name = pcs_xstrdup(dir->name);
		ldir->size = dir->stat.size;
		ldir->mtime_ns = dir->stat.mtime_ns;
		cd_list_add(&ldir->list, &h);
	}
	pcs_dirent_close(dir);

	cd_list_sort(&h, &log_dirent_cmp);

	do_apply_log_files_limits(dname, &h, nfiles, total_size, age_sec);

	cd_list_for_each_entry_safe(struct log_dirent, ldir, ldir_tmp, &h, list) {
		cd_list_del(&ldir->list);
		pcs_free(ldir);
	}

out:
	pcs_free(base_copy);
}

static void log_worker_rotate_ts(struct logrotate* l) {
	char *old_fname;

	if (l->max_nfiles != 0 || l->max_total_size != 0 || l->max_age_sec)
		logrotate_apply_limits(l->basename, l->max_nfiles, l->max_total_size, l->max_age_sec);

	old_fname = *l->fname_p;
	*l->fname_p = format_filename_ts(l->basename, l->ext, l->id);
	pcs_free(old_fname);
}

int logrotate_run(struct logrotate *l)
{
	int rc = 0;

	switch (l->rflags) {
	case PCS_LOG_ROTATE_MULTIPROC:
		log_worker_rotate_ts(l);
		break;
	case PCS_LOG_ROTATE_ENUM:
		rc = log_worker_rotate_enum(l);
		break;
	default:
		BUG();
	}

	l->request = 0; /* cleanup request */
	return rc;
}

int logrotate_maybe_run(struct logrotate *l, long long size)
{
	int ret = 1;

	if (l->request || (l->threshold && size >= l->threshold))
		ret = logrotate_run(l);

	return ret;
}

static inline char* get_basename(const char* fname)
{
	return get_basename_ext(fname, 0);
}

static int alternative_logs_present(const char *fname)
{
	int res = 0;

	char *base_name = get_basename(fname);

	int i;
	for (i = 0; log_exts[i] != NULL; i++) {
		char* alternative_name = pcs_xasprintf("%s%s", base_name, log_exts[i]);
		res = file_exists(alternative_name);
		pcs_free(alternative_name);
		if (res)
			break;
	}

	pcs_free(base_name);
	return res;
}

int logrotate_run_alt(struct logrotate *l, const char *fname)
{
	if (!alternative_logs_present(fname))
		return 1;

	return logrotate_run(l);
}
