/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_DIR_H_
#define _PCS_DIR_H_ 1

#include "pcs_types.h"
#include "timer.h"

struct pcs_stat {
	u32 mode;
	u32 nlink;
	u32 uid;
	u32 gid;
	u64 dev;		/* device on which file resides */
	u64 rdev;		/* device for CHRDEV or BLKDEV, tag for REPARSE POINT */
	u64 ino;
	u64 size;		/* in bytes */
	u64 allocated;		/* in bytes */
	u32 flags;		/* user flags on Mac, DOS attributes on Windows */
	abs_time_t mtime_ns;
	abs_time_t ctime_ns;	/* status change time */
};

typedef struct pcs_dirent {
	char		*name;
	char		*short_name;
	struct pcs_stat	stat;
} pcs_dirent_t;

#define PCS_DIRENT_STAT		1
#define PCS_DIRENT_SHORT_NAMES	2

/* Open given directory and find first entry.
 * If PCS_DIRENT_STAT flag is specified, query file stat on POSIX systems,
 * otherwise only file type in stat.mode and stat.ino are filled.
 * On Windows PCS_DIRENT_STAT flag is ignored.
 * Returns 1 if entry is found, 0 if there is no more entries and sets *out_dir pointer on success.
 * On error negative code is returned and *out_dir is left unchanged. */
PCS_API __must_check int pcs_dirent_first(const char *path, u32 flags, pcs_dirent_t **out_dir);
PCS_API __must_check int pcs_dirent_next(pcs_dirent_t *dir);

/* Close dir entry and free resources */
PCS_API void pcs_dirent_close(pcs_dirent_t *dir);

/* Coroutine-based versions. Look above for explanation. */
PCS_API __must_check int pcs_co_dirent_first(const char *path, u32 flags, pcs_dirent_t **out_dir);
PCS_API __must_check int pcs_co_dirent_next(pcs_dirent_t *dir);
PCS_API void pcs_co_dirent_close(pcs_dirent_t *dir);

#endif /* _PCS_DIR_H_ */
