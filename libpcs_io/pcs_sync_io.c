/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_types.h"

#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#ifdef __SUN__
#include <sys/fstyp.h>
#include <stropts.h>
#endif
#ifndef __WINDOWS__
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/statvfs.h>
#else
#include <io.h>
#include <WinIoCtl.h>
#include "pcs_winapi.h"
#endif

#include "pcs_config.h"
#include "pcs_sync_io.h"
#include "log.h"
#include "pcs_malloc.h"
#include "pcs_poll.h"
#include "pcs_thread.h"
#include "pcs_errno.h"
#include "pcs_compat.h"
#include "pcs_process.h"

#ifdef __linux__
#	if __GLIBC_PREREQ(2, 10)
#		include <linux/falloc.h> /* for FALLOC_FL_PUNCH_HOLE */
#	else
#		include <sys/syscall.h>
#		ifndef SYS_openat
#			ifdef __i386__
#				define SYS_openat 295 /* i386 */
#			elif defined(__x86_64__)
#				define SYS_openat 257 /* x86_64 */
#			endif /* i386 */
#		endif
#		ifndef SYS_fallocate
#			ifdef __i386__
#				define SYS_fallocate 324 /* i386 */
#			elif defined(__x86_64__)
#				define SYS_fallocate 285 /* x86_64 */
#			endif /* i386 */
#		endif
#	endif /* !__GLIBC_PREREQ(2, 10) */
#	ifndef FALLOC_FL_KEEP_SIZE
#		define FALLOC_FL_KEEP_SIZE	0x01 /* default is extend size */
#	endif
#	ifndef FALLOC_FL_PUNCH_HOLE
#		define FALLOC_FL_PUNCH_HOLE	0x02 /* de-allocates range */
#	endif
#	ifndef FALLOC_FL_ZERO_RANGE
#		define FALLOC_FL_ZERO_RANGE	0x10
#	endif
#endif /* ifdef __linux__ */

int pcs_sync_close_lock_file(const char *path, pcs_fd_t fd)
{
	int res, ret = 0;
	char *lock_fname;

	pcs_might_block();
	lock_fname = pcs_xasprintf("%s.lck", path);
	res = pcs_sync_unlink(lock_fname);
	if (res < 0)
		ret = res;

	pcs_free(lock_fname);
	res = pcs_sync_close(fd);
	if (res < 0)
		ret = res;

	return ret;
}

/* -------------------------------------------------------------------
 * synchronous I/O wrappers
 * ------------------------------------------------------------------- */

#ifndef __WINDOWS__
/* returns number of bytes written or -errno */
int pcs_sync_nwrite(pcs_fd_t fd, u64 offs, void const *buf, int sz)
{
	int w = 0;

	pcs_might_block();
	while (sz) {
		int n = pwrite(fd, buf, sz, offs);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		BUG_ON(n == 0);
		buf += n;
		offs += n;
		w += n;
		sz -= n;
	}
	return w;
}

/* returns number of bytes read */
int pcs_sync_nread(pcs_fd_t fd, u64 offs, void *buf, int sz)
{
	int r = 0;

	pcs_might_block();
	while (sz) {
		int n = pread(fd, buf, sz, offs);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			break;
		buf += n;
		offs += n;
		r += n;
		sz -= n;
	}
	return r;
}

#ifdef __linux__
#if !__GLIBC_PREREQ(2, 4)
static int openat(int dirfd, const char *pathname, int flags, mode_t mode)
{
	return syscall(SYS_openat, dirfd, pathname, flags, mode);
}
#endif /* !__GLIBC_PREREQ(2, 4) */
#if !__GLIBC_PREREQ(2, 10)
static int fallocate(int fd, int mode, off_t offset, off_t len)
{
	return syscall(SYS_fallocate, fd, mode, offset, len);
}
#endif /* !__GLIBC_PREREQ(2, 10) */
#endif /* __linux__ */

int pcs_sync_fallocate(pcs_fd_t fd, u64 offset, u64 len)
{
	pcs_might_block();
#if defined(__LINUX__)
	return fallocate(fd, 0, offset, len) == 0 ? 0 : -errno;
#elif defined(__SUN__)
	for (;;) {
		int r = posix_fallocate(fd, offset, len);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		return 0;
	}
#else
	return -ENOSYS;
#endif
}

int pcs_sync_make_sparse(pcs_fd_t fd)
{
	if (fd < 0)
		return -EBADF;
	return 0;
}

int pcs_sync_punch_hole(pcs_fd_t fd, u64 offset, u64 len)
{
	pcs_might_block();
#if defined(__LINUX__)
	for (;;) {
		int r = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, len);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		return 0;
	}
#elif defined(__MAC__) && defined(F_PUNCHHOLE)
	struct fpunchhole hole = {
		.fp_offset = offset,
		.fp_length = len,
	};
	for (;;) {
		int r = fcntl(fd, F_PUNCHHOLE, &hole);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			if (errno == ENOTTY)
				return -ENOSYS;
			return -errno;
		}
		return 0;
	}
#elif defined(__SUN__)
	struct flock64 hole = {
		.l_start = offset,
		.l_len = len,
		.l_whence = SEEK_SET,
	};
	for (;;) {
		int r = fcntl(fd, F_FREESP64, &hole);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		return 0;
	}
#else
	return -ENOSYS;
#endif
}

int pcs_sync_zero_range(pcs_fd_t fd, u64 offset, u64 len)
{
	pcs_might_block();
#if defined(__LINUX__)
	while (1) {
		int r = fallocate(fd, FALLOC_FL_ZERO_RANGE, offset, len);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		return 0;
	}
#else
	return -ENOSYS;
#endif
}

/* returns 0 or -errno */
int pcs_sync_ftruncate(pcs_fd_t fd, u64 len)
{
	pcs_might_block();
	for (;;) {
		int r = ftruncate(fd, len);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		return 0;
	}
}

int pcs_sync_fsync(pcs_fd_t fd)
{
	pcs_might_block();
	for (;;) {
		int r = fsync(fd);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		return 0;
	}
}

int pcs_sync_fdatasync(pcs_fd_t fd)
{
	pcs_might_block();
	for (;;) {
		int r =
#ifdef __linux__
			fdatasync(fd);
#else
			fsync(fd);
#endif
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		return 0;
	}
}

/* returns 0 if ok or -errno if error */
int pcs_sync_swrite(pcs_fd_t fd, void const *buf, int sz)
{
	int w = sz;

	pcs_might_block();
	while (w) {
		int n = write(fd, buf, w);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		BUG_ON(n == 0);
		buf = (const char*)buf + n;
		w -= n;
	}
	return sz;
}

/* returns number of bytes read */
int pcs_sync_sread(pcs_fd_t fd, void *buf, int sz)
{
	int r = 0;

	pcs_might_block();
	while (sz) {
		int n = read(fd, buf, sz);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			break;
		buf = (char*)buf + n;
		r += n;
		sz -= n;
	}
	return r;
}

int pcs_sync_getfsize(pcs_fd_t fd, u64 * size)
{
	struct stat st;
	pcs_might_block();
	if (fstat(fd, &st) < 0)
		return -errno;
	*size = st.st_size;
	return 0;
}

int pcs_sync_open(const char * pathname, int flags, int mode, pcs_fd_t * out_fd)
{
	pcs_might_block();
	pcs_fd_t fd = -1;
	while (1) {
		fd = open(pathname, flags, mode);
		if (fd >= 0)
			break;
		if (errno != EINTR)
			return -errno;
	}
	*out_fd = fd;
	return 0;
}

int pcs_sync_openat(pcs_fd_t dirfd, const char * pathname, int flags, int mode, pcs_fd_t * out_fd)
{
	pcs_might_block();
	pcs_fd_t fd = -1;
	while (1) {
		fd = openat(dirfd, pathname, flags, mode);
		if (fd >= 0)
			break;
		if (errno != EINTR)
			return -errno;
	}
	*out_fd = fd;
	return 0;
}

int pcs_sync_close(pcs_fd_t fd)
{
	pcs_might_block();
	while (1) {
		int err = close(fd);
		if (!err)
			return 0;
		if (errno != EINTR)
			return -errno;
	}
}

int pcs_sync_mkdir(const char *pathname, int mode)
{
	pcs_might_block();
	return mkdir(pathname, mode) == 0 ? 0 : -errno;
}

int pcs_sync_rmdir(const char *pathname)
{
	pcs_might_block();
	return rmdir(pathname) == 0 ? 0 : -errno;
}

int pcs_sync_unlink(const char * pathname)
{
	pcs_might_block();
	return unlink(pathname) == 0 ? 0 : -errno;
}
int pcs_sync_rename(const char * oldpath, const char * newpath)
{
	pcs_might_block();
	return rename(oldpath, newpath) == 0 ? 0 : -errno;
}

int pcs_sync_lseek(pcs_fd_t fd, u64 offs, int origin, u64 *new_offs)
{
	pcs_might_block();
	off_t offset = lseek(fd, (off_t)offs, origin);
	if (offset < 0)
		return -errno;
	if (new_offs)
		*new_offs = (u64)offset;
	return 0;
}

int pcs_sync_ioctl(pcs_fd_t fd, unsigned long int cmd, void *data)
{
	pcs_might_block();
	int r = ioctl(fd, cmd, data);
	return (r >= 0) ? r : -errno;
}

int pcs_sync_lock(pcs_fd_t fd, int cmd, short int type, u64 offs, u64 len)
{
	pcs_might_block();
	struct flock lock = {
		.l_start = offs,
		.l_len = len,
		.l_type = type,
		.l_whence = SEEK_SET,
	};
	while (1) {
		if (fcntl(fd, cmd, &lock) == 0)
			return 0;
		if (errno != EINTR)
			return -errno;
	}
}

static abs_time_t timespec2ns(const struct timespec *ts)
{
	return (abs_time_t)ts->tv_sec * 1000*1000*1000 + ts->tv_nsec;
}

void pcs_stat2pcs(const struct stat *st, struct pcs_stat *res)
{
	res->mode = st->st_mode;
	res->nlink = st->st_nlink;
	res->uid = st->st_uid;
	res->gid = st->st_gid;
	res->dev = st->st_dev;
	res->rdev = st->st_rdev;
	res->ino = st->st_ino;
	res->size = st->st_size;
	res->allocated = 512ULL * st->st_blocks;
#if defined(__LINUX__) || defined(__SUN__)
	res->flags = 0;
	res->mtime_ns = timespec2ns(&st->st_mtim);
	res->ctime_ns = timespec2ns(&st->st_ctim);
#elif defined(__MAC__)
	res->flags = st->st_flags;
	res->mtime_ns = timespec2ns(&st->st_mtimespec);
	res->ctime_ns = timespec2ns(&st->st_ctimespec);
#else
#error Not implemented
#endif
}

int pcs_sync_stat(const char *path, int flags, struct pcs_stat *res)
{
	struct stat st;

	pcs_might_block();
	int rc = flags & PCS_SYNC_NOFOLLOW
		? lstat(path, &st)
		: stat(path, &st);
	if (rc)
		return -errno;

	pcs_stat2pcs(&st, res);
	return 0;
}

int pcs_sync_fstat(pcs_fd_t fd, struct pcs_stat *res)
{
	struct stat st;

	pcs_might_block();
	if (fstat(fd, &st) < 0)
		return -errno;

	pcs_stat2pcs(&st, res);
	return 0;
}

void pcs_statvfs2pcs(const struct statvfs *st, struct pcs_statvfs *res)
{
	res->bsize = st->f_bsize;
	res->frsize = st->f_frsize;
	res->blocks = st->f_blocks;
	res->bfree = st->f_bfree;
	res->bavail = st->f_bavail;
	res->files = st->f_files;
	res->ffree = st->f_ffree;
	res->favail = st->f_favail;
	res->fsid = st->f_fsid;
	res->flag = st->f_flag;
	res->namemax = st->f_namemax;
}

int pcs_sync_statvfs(const char *path, struct pcs_statvfs *res)
{
	struct statvfs st;

	pcs_might_block();
	if (statvfs(path, &st) < 0)
		return -errno;

	pcs_statvfs2pcs(&st, res);
	return 0;
}

int pcs_sync_fstatvfs(pcs_fd_t fd, struct pcs_statvfs *res)
{
	struct statvfs st;

	pcs_might_block();
	if (fstatvfs(fd, &st) < 0)
		return -errno;

	pcs_statvfs2pcs(&st, res);
	return 0;
}

int pcs_sync_create_lock_file(const char *path, pcs_fd_t *out_fd)
{
	int ret = 0;
	pcs_fd_t lock_fd;
	char *lock_fname;

	pcs_might_block();
	lock_fname = pcs_xasprintf("%s.lck", path);

	if ((lock_fd = open(lock_fname, O_CREAT | O_WRONLY, 0600)) < 0) {
		ret = -errno;
		goto done;
	}
#ifdef __SUN__
	if ((ret = pcs_sync_lock(lock_fd, F_SETLK, F_WRLCK, 0, 0))) {
#else
	if (flock(lock_fd, LOCK_EX | LOCK_NB) < 0) {
		ret = -errno;
#endif
		close(lock_fd);
		goto done;
	}

	*out_fd = lock_fd;
done:
	pcs_free(lock_fname);
	return ret;
}

pcs_fd_t pcs_stdin_fd(void)
{
	return STDIN_FILENO;
}

pcs_fd_t pcs_stdout_fd(void)
{
	return STDOUT_FILENO;
}

pcs_fd_t pcs_stderr_fd(void)
{
	return STDERR_FILENO;
}

#else /* __WINDOWS__ */

static void overlapped_init(OVERLAPPED *ov, HANDLE hEvent, u64 offs)
{
	memset(ov, 0, sizeof(*ov));
	/* Prevent completion port notification by setting low-order bit of the hEvent member.
	 * See description of the lpOverlapped [out] parameter of the GetQueuedCompletionStatus
	 * function https://msdn.microsoft.com/en-us/library/windows/desktop/aa364986(v=vs.85).aspx */
	ov->hEvent = (HANDLE)((uintptr_t)hEvent | 1);
	ov->Offset = (DWORD)offs;
	ov->OffsetHigh = (DWORD)(offs >> 32);
}

static int sync_write(pcs_fd_t fd, u64 offs, void const *buf, int sz)
{
	OVERLAPPED ov;

	HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!hEvent)
		return -(int)GetLastError();

	int total = 0;
	pcs_might_block();
	while (sz) {
		DWORD n;
		overlapped_init(&ov, hEvent, offs);
		/* This will work for files opened with and without FILE_FLAG_OVERLAPPED.
		   In later case the function will block. */
		if (!WriteFile(fd, buf, sz, &n, &ov)) {
			if (GetLastError() != ERROR_IO_PENDING) {
				total = -(int)GetLastError();
				break;
			}
			if (!GetOverlappedResult(fd, &ov, &n, TRUE)) {
				total = -(int)GetLastError();
				break;
			}
		}
		if (n == 0)
			break;
		buf = (const char*)buf + n;
		offs += n;
		total += n;
		sz -= n;
	}
	CloseHandle(hEvent);
	return total;
}

int pcs_sync_nwrite(pcs_fd_t fd, u64 offs, void const *buf, int sz)
{
	int rc = sync_write(fd, offs, buf, sz);
	if (rc < 0)
		return rc;
	if (rc < sz)
		return -ERROR_DISK_FULL;
	return rc;
}

int pcs_sync_nread(pcs_fd_t fd, u64 offs, void *buf, int sz)
{
	OVERLAPPED ov;
	HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!hEvent)
		return -(int)GetLastError();

	int err = ERROR_SUCCESS;
	int total = 0;
	pcs_might_block();
	while (sz) {
		DWORD n;
		overlapped_init(&ov, hEvent, offs);
		/* This will work for files opened with and without FILE_FLAG_OVERLAPPED.
		   In later case the function will block. */
		if (!ReadFile(fd, buf, sz, &n, &ov)) {
			err = GetLastError();
			if (err != ERROR_IO_PENDING)
				break;
			if (!GetOverlappedResult(fd, &ov, &n, TRUE)) {
				err = GetLastError();
				break;
			}
			err = ERROR_SUCCESS;
		}
		if (n == 0)
			break;

		buf = (char*)buf + n;
		offs += n;
		total += n;
		sz -= n;
	}
	CloseHandle(hEvent);
	switch (err) {
	case ERROR_SUCCESS:
	case ERROR_HANDLE_EOF:
	case ERROR_BROKEN_PIPE:
		return total;
	default:
		return -err;
	}
}

int pcs_sync_fallocate(pcs_fd_t fd, u64 offset, u64 len)
{
	return -ERROR_NOT_SUPPORTED;
}

static int overlapped_device_io_control(HANDLE fd, DWORD code, void *buf, DWORD buf_size)
{
	int err = 0;
	OVERLAPPED ov;
	HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!hEvent)
		return -(int)GetLastError();

	pcs_might_block();

	overlapped_init(&ov, hEvent, 0);
	if (!DeviceIoControl(fd, code, buf, buf_size, NULL, 0, NULL, &ov)) {
		err = GetLastError();
		if (err != ERROR_IO_PENDING)
			goto done;
	}

	DWORD n;
	err = GetOverlappedResult(fd, &ov, &n, TRUE) ? 0 : GetLastError();

done:
	CloseHandle(hEvent);
	return -err;
}

/* pcs_sync_make_sparse() and pcs_sync_punch_hole() will return ERROR_INVALID_FUNCTION if file system
 * does not support sparse files. Beware that pcs_sync_make_sparse() might succeed on SMB volumes, so
 * always check pcs_sync_punch_hole() errors. */
int pcs_sync_make_sparse(pcs_fd_t fd)
{
	return overlapped_device_io_control(fd, FSCTL_SET_SPARSE, NULL, 0);
}

int pcs_sync_punch_hole(pcs_fd_t fd, u64 offset, u64 len)
{
	FILE_ZERO_DATA_INFORMATION fzdi;
	fzdi.FileOffset.QuadPart = offset;
	fzdi.BeyondFinalZero.QuadPart = offset + len;
	return overlapped_device_io_control(fd, FSCTL_SET_ZERO_DATA, &fzdi, sizeof(fzdi));
}

int pcs_sync_ftruncate(pcs_fd_t fd, u64 len)
{
	LARGE_INTEGER new_len, old_pos;
	pcs_might_block();

	new_len.QuadPart = 0;
	if (!SetFilePointerEx(fd, new_len, &old_pos, FILE_CURRENT))
		return -(int)GetLastError();

	new_len.QuadPart = len;
	if (!SetFilePointerEx(fd, new_len, NULL, FILE_BEGIN))
		return -(int)GetLastError();

	if (!SetEndOfFile(fd))
		return -(int)GetLastError();

	if (!SetFilePointerEx(fd, old_pos, NULL, FILE_BEGIN))
		return -(int)GetLastError();

	return 0;
}

int pcs_sync_fsync(pcs_fd_t fd)
{
	pcs_might_block();
	if (!FlushFileBuffers(fd))
		return -(int)GetLastError();

	return 0;
}

int pcs_sync_fdatasync(pcs_fd_t fd)
{
	return pcs_sync_fsync(fd);
}

/* returns 0 if ok or -errno if error */
int pcs_sync_swrite(pcs_fd_t fd, void const *buf, int sz)
{
	return sync_write(fd, 0, buf, sz);
}

/* returns number of bytes read */
int pcs_sync_sread(pcs_fd_t fd, void *buf, int sz)
{
	return pcs_sync_nread(fd, 0, buf, sz);
}

int pcs_sync_getfsize(pcs_fd_t fd, u64 * size)
{
	LARGE_INTEGER sz;
	pcs_might_block();
	if (!GetFileSizeEx(fd, &sz))
		return -(int)GetLastError();
	*size = sz.QuadPart;
	return 0;
}

int pcs_sync_open(const char * pathname, int flags, int mode, pcs_fd_t * out_fd)
{
	DWORD access;
	DWORD share;
	DWORD disposition;
	DWORD attributes = 0;
	HANDLE file;
	int current_umask;

	current_umask = umask(0);
	umask(current_umask);

	/* convert flags and mode to CreateFile parameters */
	switch (flags & (_O_RDONLY | _O_WRONLY | _O_RDWR)) {
	case _O_RDONLY:
		access = GENERIC_READ;
		break;
	case _O_WRONLY:
		access = GENERIC_WRITE;
		break;
	case _O_RDWR:
		access = GENERIC_READ | GENERIC_WRITE;
		break;
	default:
		return -ERROR_INVALID_PARAMETER;
	}

	/*
	* Here is where we deviate significantly from what CRT's _open()
	* does. We indiscriminately use all the sharing modes, to match
	* UNIX semantics. In particular, this ensures that the file can
	* be deleted even whilst it's open, fixing issue #1449.
	*/
	share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

	switch (flags & (_O_CREAT | _O_EXCL | _O_TRUNC)) {
	case 0:
	case _O_EXCL:
		disposition = OPEN_EXISTING;
		break;
	case _O_CREAT:
		disposition = OPEN_ALWAYS;
		break;
	case _O_CREAT | _O_EXCL:
	case _O_CREAT | _O_TRUNC | _O_EXCL:
		disposition = CREATE_NEW;
		break;
	case _O_TRUNC:
	case _O_TRUNC | _O_EXCL:
		disposition = TRUNCATE_EXISTING;
		break;
	case _O_CREAT | _O_TRUNC:
		disposition = CREATE_ALWAYS;
		break;
	default:
		return -ERROR_INVALID_PARAMETER;
	}

	attributes |= FILE_ATTRIBUTE_NORMAL;
	if (flags & _O_CREAT) {
		if (!((mode & ~current_umask) & _S_IWRITE)) {
			attributes |= FILE_ATTRIBUTE_READONLY;
		}
	}

	if (flags & _O_TEMPORARY) {
		attributes |= FILE_FLAG_DELETE_ON_CLOSE | FILE_ATTRIBUTE_TEMPORARY;
		access |= DELETE;
	}

	if (flags & _O_SHORT_LIVED) {
		attributes |= FILE_ATTRIBUTE_TEMPORARY;
	}

	switch (flags & (_O_SEQUENTIAL | _O_RANDOM)) {
	case 0:
		break;
	case _O_SEQUENTIAL:
		attributes |= FILE_FLAG_SEQUENTIAL_SCAN;
		break;
	case _O_RANDOM:
		attributes |= FILE_FLAG_RANDOM_ACCESS;
		break;
	default:
		return -ERROR_INVALID_PARAMETER;
	}

	if (flags & O_DIRECT)
		attributes |= FILE_FLAG_NO_BUFFERING;

	/* Always open files in asynchronous mode */
	attributes |= FILE_FLAG_OVERLAPPED;

	WCHAR * w_pathname = pcs_utf8_to_utf16(pathname, -1);
	if (!w_pathname)
		return -(int)GetLastError();

	pcs_might_block();

	file = CreateFileW(w_pathname,
		access,
		share,
		NULL,
		disposition,
		attributes,
		NULL);

	int err = -(int)GetLastError();
	pcs_free(w_pathname);
	if (file == INVALID_HANDLE_VALUE)
		return err;

	*out_fd = file;
	return 0;
}

int pcs_sync_openat(pcs_fd_t dirfd, const char * pathname, int flag, int mode, pcs_fd_t * out_fd)
{
	/* Windows has openat(): https://stackoverflow.com/a/32554138 */
	pcs_fatal("pcs_sync_openat() not implemented on windows");
}

int pcs_sync_close(pcs_fd_t fd)
{
	pcs_might_block();
	return CloseHandle(fd) ? 0 : -(int)GetLastError();
}

int pcs_sync_mkdir(const char *pathname, int mode)
{
	WCHAR * w_pathname = pcs_utf8_to_utf16(pathname, -1);
	if (!w_pathname)
		return -(int)GetLastError();

	pcs_might_block();
	int ret = CreateDirectoryW(w_pathname, NULL) ? 0 : -(int)GetLastError();
	pcs_free(w_pathname);
	return ret;
}

int pcs_sync_rmdir(const char *pathname)
{
	WCHAR * w_pathname = pcs_utf8_to_utf16(pathname, -1);
	if (!w_pathname)
		return -(int)GetLastError();

	pcs_might_block();
	int ret = RemoveDirectoryW(w_pathname) ? 0 : -(int)GetLastError();
	pcs_free(w_pathname);
	return ret;
}

int pcs_sync_unlink(const char * pathname)
{
	WCHAR * w_pathname = pcs_utf8_to_utf16(pathname, -1);
	if (!w_pathname)
		return -(int)GetLastError();

	pcs_might_block();
	int ret = DeleteFileW(w_pathname) ? 0 : -(int)GetLastError();
	pcs_free(w_pathname);
	return ret;
}

int pcs_sync_rename(const char * oldname, const char * newname)
{
	int err = 0;
	WCHAR *w_old, *w_new;
	w_old = pcs_utf8_to_utf16(oldname, -1);
	if (!w_old)
		return -(int)GetLastError();
	w_new = pcs_utf8_to_utf16(newname, -1);
	if (!w_new) {
		err = -(int)GetLastError();
		pcs_free(w_old);
		return err;
	}

	pcs_might_block();
	if (!MoveFileExW(w_old, w_new, MOVEFILE_REPLACE_EXISTING))
		err = -(int)GetLastError();

	pcs_free(w_old);
	pcs_free(w_new);
	return err;
}

int pcs_sync_lseek(pcs_fd_t fd, u64 offs, int origin, u64 *new_offs)
{
	pcs_might_block();
	LARGE_INTEGER offset;
	offset.QuadPart = (LONGLONG)offs;
	offset.LowPart = SetFilePointer(fd, offset.LowPart, &offset.HighPart, origin);
	if (offset.LowPart < 0)
		return -(int)GetLastError();
	if (new_offs)
		*new_offs = (u64)offset.QuadPart;
	return 0;
}

int pcs_sync_ioctl(pcs_fd_t fd, unsigned long int cmd, void *data)
{
	pcs_fatal("FIXME: implement pcs_sync_ioctl() for windows");
}

int pcs_sync_lock(pcs_fd_t fd, int cmd, short int type, u64 offs, u64 len)
{
	HANDLE event = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!event)
		return -(int)GetLastError();

	OVERLAPPED ov;
	overlapped_init(&ov, event, offs);

	const DWORD len_lo = len & 0xffffffffu;
	const DWORD len_hi = len >> 32;

	int err = 0;
	BOOL res = 1;
	DWORD flags = 0;
	switch (cmd) {
	case F_SETLKW:
		break;
	case F_SETLK:
		flags |= LOCKFILE_FAIL_IMMEDIATELY;
		break;
	default:
		err = ERROR_INVALID_PARAMETER;
		goto fail;
	}

	switch (type) {
	case F_UNLCK:
		res = UnlockFileEx(fd, 0, len_lo, len_hi, &ov);
		break;
	case F_WRLCK:
		flags |= LOCKFILE_EXCLUSIVE_LOCK;
		/* fall through */
	case F_RDLCK:
		res = LockFileEx(fd, flags, 0, len_lo, len_hi, &ov);
		break;
	default:
		err = ERROR_INVALID_PARAMETER;
	}
	if (!res && (err = GetLastError()) == ERROR_IO_PENDING) {
		DWORD n;
		err = GetOverlappedResult(fd, &ov, &n, TRUE) ? 0 : GetLastError();
	}
fail:
	CloseHandle(event);
	return -err;
}

int pcs_sync_stat(const char *path, int flags, struct pcs_stat *res)
{
	WCHAR *w_pathname = pcs_utf8_to_utf16(path, -1);
	if (!w_pathname)
		return -(int)GetLastError();

	pcs_might_block();

	/* This flag is required to open directories */
	int file_flags = FILE_FLAG_BACKUP_SEMANTICS;
	if ((flags & PCS_SYNC_NOFOLLOW))
		file_flags |= FILE_FLAG_OPEN_REPARSE_POINT;

	HANDLE handle = CreateFileW(w_pathname,
		FILE_READ_ATTRIBUTES,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		file_flags,
		NULL);
	int rc = (handle == INVALID_HANDLE_VALUE) ? -(int)GetLastError() : 0;
	pcs_free(w_pathname);
	if (rc)
		return rc;

	rc = pcs_sync_fstat(handle, res);
	CloseHandle(handle);
	return rc;
}

int pcs_sync_fstat(pcs_fd_t fd, struct pcs_stat *res)
{
	FILE_ALL_INFORMATION file_info;
	FILE_FS_VOLUME_INFORMATION volume_info;
	FILE_ATTRIBUTE_TAG_INFORMATION attr_info;
	IO_STATUS_BLOCK io_status;
	NTSTATUS nt_status;

	pcs_might_block();

	nt_status = NtQueryInformationFilePtr(fd,
		&io_status,
		&file_info,
		sizeof file_info,
		FileAllInformation);

	if (NT_ERROR(nt_status))
		return -(int)RtlNtStatusToDosErrorPtr(nt_status);

	nt_status = NtQueryVolumeInformationFilePtr(fd,
		&io_status,
		&volume_info,
		sizeof volume_info,
		FileFsVolumeInformation);

	if (io_status.Status == STATUS_NOT_IMPLEMENTED)
		res->dev = 0;
	else if (NT_ERROR(nt_status))
		return -(int)RtlNtStatusToDosErrorPtr(nt_status);
	else
		res->dev = volume_info.VolumeSerialNumber;

	if (file_info.BasicInformation.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		nt_status = NtQueryInformationFilePtr(fd,
			&io_status,
			&attr_info,
			sizeof attr_info,
			FileAttributeTagInformation);

		if (NT_ERROR(nt_status))
			return -(int)RtlNtStatusToDosErrorPtr(nt_status);

		res->mode = S_IFLNK;
		res->size = 0;
		res->rdev = attr_info.ReparseTag;
	} else if (file_info.BasicInformation.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		res->mode = S_IFDIR;
		res->size = 0;
		res->rdev = 0;
	} else {
		res->mode = S_IFREG;
		res->size = file_info.StandardInformation.EndOfFile.QuadPart;
		res->rdev = 0;
	}

	res->ino = file_info.InternalInformation.IndexNumber.QuadPart;
	res->allocated = file_info.StandardInformation.AllocationSize.QuadPart;
	res->nlink = file_info.StandardInformation.NumberOfLinks;
	res->flags = file_info.BasicInformation.FileAttributes;

	res->ctime_ns = filetime2ns((FILETIME *)&file_info.BasicInformation.ChangeTime);
	res->mtime_ns = filetime2ns((FILETIME *)&file_info.BasicInformation.LastWriteTime);

	res->uid = 0;
	res->gid = 0;

	return 0;
}

int pcs_sync_statvfs(const char *path, struct pcs_statvfs *res)
{
	int r = 0;
	ULARGE_INTEGER nr_free_bytes_avail, nr_free_bytes, nr_bytes_total;
	WCHAR *w_path = pcs_utf8_to_utf16(path, -1);
	if (!w_path)
		return -(int)GetLastError();

	if (!GetDiskFreeSpaceExW(w_path, &nr_free_bytes_avail, &nr_bytes_total, &nr_free_bytes)) {
		r = -(int)GetLastError();
		goto out;
	}

	memset(res, 0, sizeof(*res));

	/* GetDiskFreeSpaceEx() does not return FS block size, so hardcode it to 4096 bytes, which is the default for NTFS. */
	res->bsize = res->frsize = 4096;

	res->blocks = nr_bytes_total.QuadPart / res->frsize;
	res->bfree = nr_free_bytes.QuadPart / res->frsize;
	res->bavail = nr_free_bytes_avail.QuadPart / res->frsize;

out:
	pcs_free(w_path);

	return r;
}

int pcs_sync_create_lock_file(const char *path, pcs_fd_t *out_fd)
{
	int err = 0;
	HANDLE file;
	char *lock_fname;
	WCHAR *w_lock_fname;

	pcs_might_block();

	lock_fname = pcs_xasprintf("%s.lck", path);
	err = -(int)GetLastError();
	w_lock_fname = pcs_utf8_to_utf16(lock_fname, -1);
	pcs_free(lock_fname);
	if (!w_lock_fname)
		return err;

	file = CreateFileW(w_lock_fname, FILE_GENERIC_WRITE, FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, 0, NULL);
	err = -(int)GetLastError();
	pcs_free(w_lock_fname);
	if (file == INVALID_HANDLE_VALUE)
		return err;

	*out_fd = file;
	return 0;
}


pcs_fd_t pcs_stdin_fd(void)
{
	return GetStdHandle(STD_INPUT_HANDLE);
}

pcs_fd_t pcs_stdout_fd(void)
{
	return GetStdHandle(STD_OUTPUT_HANDLE);
}

pcs_fd_t pcs_stderr_fd(void)
{
	return GetStdHandle(STD_ERROR_HANDLE);
}

#endif /* __WINDOWS__ */
