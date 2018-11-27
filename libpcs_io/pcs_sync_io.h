/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_SYNC_IO_H_
#define _PCS_SYNC_IO_H_ 1

#include "pcs_dir.h"

/* returns number of bytes or -errno */
PCS_API int pcs_sync_nwrite(pcs_fd_t fd, u64 offs, void const *buf, int sz);
PCS_API int pcs_sync_nread(pcs_fd_t fd, u64 offs, void *buf, int sz);
PCS_API int pcs_sync_swrite(pcs_fd_t fd, void const *buf, int sz);
PCS_API int pcs_sync_sread(pcs_fd_t fd, void *buf, int sz);

/* returns 0 or -errno */
PCS_API int pcs_sync_fallocate(pcs_fd_t fd, u64 offset, u64 len);
/* before punching holes file must be marked as sparse on Windows */
PCS_API int pcs_sync_make_sparse(pcs_fd_t fd);
PCS_API int pcs_sync_punch_hole(pcs_fd_t fd, u64 offset, u64 len);
PCS_API int pcs_sync_zero_range(pcs_fd_t fd, u64 offset, u64 len);
PCS_API int pcs_sync_ftruncate(pcs_fd_t fd, u64 len);
PCS_API int pcs_sync_fsync(pcs_fd_t fd);
PCS_API int pcs_sync_fdatasync(pcs_fd_t fd);
PCS_API int pcs_sync_getfsize(pcs_fd_t fd, u64 * size);
PCS_API int pcs_sync_open(const char * pathname, int flag, int mode, pcs_fd_t * out_fd);
PCS_API int pcs_sync_openat(pcs_fd_t dirfd, const char * pathname, int flag, int mode, pcs_fd_t * out_fd);
PCS_API int pcs_sync_close(pcs_fd_t fd);
PCS_API int pcs_sync_mkdir(const char *pathname, int mode);
PCS_API int pcs_sync_rmdir(const char *pathname);
PCS_API int pcs_sync_unlink(const char * pathname);
PCS_API int pcs_sync_rename(const char * oldpath, const char * newpath);
PCS_API int pcs_sync_lseek(pcs_fd_t fd, u64 offs, int origin, u64 *new_offs);
PCS_API int pcs_sync_ioctl(pcs_fd_t fd, unsigned long int cmd, void *data);
/* Try to lock or unlock file range.
 * Cmd is F_SETLK|F_SETLKW or F_OFD_SETLK|F_OFD_SETLKW (Linux and Mac only).
 * Type is one of F_RDLCK|F_WRLCK|F_UNLCK.
 * Note: range locks are mandatory on Windows, advisory on UNIX.
 * Returns 0 if lock is acquired, -EACCES or -EAGAIN if lock is held by another process */
PCS_API int pcs_sync_lock(pcs_fd_t fd, int cmd, short int type, u64 offs, u64 len);
int pcs_sync_create_lock_file(const char *path, pcs_fd_t *out_fd);
int pcs_sync_close_lock_file(const char *path, pcs_fd_t fd);

struct stat;
struct pcs_stat;
#define PCS_SYNC_NOFOLLOW (1 << 0)
PCS_API int pcs_sync_stat(const char *path, int flags, struct pcs_stat *res);
PCS_API int pcs_sync_fstat(pcs_fd_t fd, struct pcs_stat *res);
void pcs_stat2pcs(const struct stat *st, struct pcs_stat *res);

struct statvfs;

struct pcs_statvfs
{
	u64 bsize;    /* Filesystem block size */
	u64 frsize;   /* Fragment size */
	u64 blocks;   /* Size of fs in @frsize units */
	u64 bfree;    /* Number of free blocks */
	u64 bavail;   /* Number of free blocks for unprivileged users */
	u64 files;    /* Number of inodes */
	u64 ffree;    /* Number of free inodes */
	u64 favail;   /* Number of free inodes for unprivileged users */
	u64 fsid;     /* Filesystem ID */
	u64 flag;     /* Mount flags */
	u64 namemax;  /* Maximum filename length */
};

PCS_API int pcs_sync_statvfs(const char *path, struct pcs_statvfs *res);
PCS_API int pcs_sync_fstatvfs(pcs_fd_t fd, struct pcs_statvfs *res);
void pcs_statvfs2pcs(const struct statvfs *st, struct pcs_statvfs *res);

PCS_API pcs_fd_t pcs_stdin_fd(void);
PCS_API pcs_fd_t pcs_stdout_fd(void);
PCS_API pcs_fd_t pcs_stderr_fd(void);

#endif /* _PCS_SYNC_IO_H_ */
