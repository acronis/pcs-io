/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_dir.h"
#include "pcs_process.h"
#include "pcs_coroutine.h"
#include "pcs_compat.h"
#include "pcs_malloc.h"
#include "pcs_sync_io.h"
#include "pcs_co_io.h"
#include "pcs_winapi.h"
#include "bug.h"
#include "log.h"
#ifndef __WINDOWS__
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#endif
#ifdef __MAC__
#include <sys/syslimits.h>
#endif

#ifdef __WINDOWS__

struct pcs_dirent_priv {
	pcs_dirent_t		dirent;
	HANDLE			handle;
	FILE_INFORMATION_CLASS	level;
	u32			size;
	u32			pos;
	ULONG_PTR		buffer[8 * 1024 / sizeof(ULONG_PTR)];
};

static int empty_result(const struct pcs_dirent_priv *dir)
{
	/* https://pmc.acronis.com/browse/ABR-132626
	 * SMB share on AltaVault can return success but useless dir information:
	 * only struct offset field is valid, other filled with zeros */
	const FILE_FULL_DIR_INFORMATION *info = (FILE_FULL_DIR_INFORMATION*)dir->buffer;
	return info->FileNameLength == 0;
}

static int is_unsupported(NTSTATUS status)
{
	switch (status) {
	case STATUS_INVALID_PARAMETER:
	case STATUS_NOT_SUPPORTED:
	case STATUS_INVALID_LEVEL:
	case STATUS_INVALID_INFO_CLASS:
		return 1;
	default:
		return 0;
	}
}

__must_check int pcs_dirent_first(const char *path, u32 flags, pcs_dirent_t **out_dir)
{
	WCHAR *wpath = pcs_utf8_to_utf16(path, -1);
	if (!wpath)
		return -(int)GetLastError();

	HANDLE handle = CreateFileW(wpath, FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
					NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (handle == INVALID_HANDLE_VALUE) {
		int err = GetLastError();
		pcs_free(wpath);
		return -err;
	}

	struct pcs_dirent_priv *dir = pcs_xmalloc(sizeof(*dir));
	memset(dir, 0, offsetof(struct pcs_dirent_priv, buffer));
	dir->handle = handle;
	dir->level = (flags & PCS_DIRENT_SHORT_NAMES) ? FileIdBothDirectoryInformation : FileIdFullDirectoryInformation;

	IO_STATUS_BLOCK iosb;
	FILE_FS_VOLUME_INFORMATION vol_info;
	NTSTATUS status = NtQueryVolumeInformationFilePtr(dir->handle, &iosb, &vol_info, sizeof(vol_info), FileFsVolumeInformation);
	if (status == STATUS_SUCCESS)
		dir->dirent.stat.dev = vol_info.VolumeSerialNumber;

	status = NtQueryDirectoryFilePtr(dir->handle, NULL, NULL, NULL, &iosb, dir->buffer, sizeof(dir->buffer), dir->level, FALSE, NULL, TRUE);
	if (is_unsupported(status) || (status == STATUS_SUCCESS && empty_result(dir))) {
		dir->level = (flags & PCS_DIRENT_SHORT_NAMES) ? FileBothDirectoryInformation : FileFullDirectoryInformation;
		status = NtQueryDirectoryFilePtr(dir->handle, NULL, NULL, NULL, &iosb, dir->buffer, sizeof(dir->buffer), dir->level, FALSE, NULL, TRUE);
	}

	if (status == STATUS_NO_SUCH_FILE || status == STATUS_NO_MORE_FILES) {
		*out_dir = &dir->dirent;
		return 0;
	}

	if (status != STATUS_SUCCESS) {
		pcs_dirent_close(&dir->dirent);
		return -(int)RtlNtStatusToDosErrorPtr(status);
	}

	dir->size = (u32)iosb.Information;
	int rc;
	if ((rc = pcs_dirent_next(&dir->dirent)) < 0) {
		pcs_dirent_close(&dir->dirent);
		return rc;
	}

	*out_dir = &dir->dirent;
	return rc;
}

__must_check int pcs_dirent_firstat(pcs_fd_t dirfd, const char *pathname, u32 flags, pcs_dirent_t **out_dir)
{
	BUG(); // not implemented for Windows
}

static __must_check int __dirent_next(struct pcs_dirent_priv *dir)
{
	pcs_free(dir->dirent.name);
	dir->dirent.name = NULL;
	pcs_free(dir->dirent.short_name);
	dir->dirent.short_name = NULL;

	while (dir->pos < dir->size) {
		FILE_FULL_DIR_INFORMATION *info = (FILE_FULL_DIR_INFORMATION *)((char *)dir->buffer + dir->pos);
		if (info->NextEntryOffset)
			dir->pos += info->NextEntryOffset;
		else
			dir->pos = dir->size;

		WCHAR* name = NULL;
		u64 ino = 0;
		switch (dir->level) {
			case FileFullDirectoryInformation:
				name = ((FILE_FULL_DIR_INFORMATION *)info)->FileName;
				break;

			case FileBothDirectoryInformation:
				name = ((FILE_BOTH_DIR_INFORMATION *)info)->FileName;
				break;

			case FileIdBothDirectoryInformation:
				name = ((FILE_ID_BOTH_DIR_INFORMATION *)info)->FileName;
				ino = ((FILE_ID_BOTH_DIR_INFORMATION *)info)->FileId.QuadPart;
				break;

			case FileIdFullDirectoryInformation:
				name = ((FILE_ID_FULL_DIR_INFORMATION *)info)->FileName;
				ino = ((FILE_ID_FULL_DIR_INFORMATION *)info)->FileId.QuadPart;
				break;

			default:
				BUG();
		}

		u32 name_len = info->FileNameLength / sizeof(WCHAR);
		if ((name_len == 1 && name[0] == '.') || (name_len == 2 && name[0] == '.' && name[1] == '.'))
			continue;

		if (name_len == 0)
			continue;

		dir->dirent.name = pcs_utf16_to_utf8(name, name_len);
		dir->dirent.stat.mtime_ns = filetime2ns((FILETIME *)&info->LastWriteTime);
		dir->dirent.stat.ctime_ns = filetime2ns((FILETIME *)&info->ChangeTime);
		dir->dirent.stat.size = info->EndOfFile.QuadPart;
		dir->dirent.stat.allocated = info->AllocationSize.QuadPart;
		dir->dirent.stat.flags = info->FileAttributes;
		dir->dirent.stat.ino = ino;
		dir->dirent.stat.rdev = 0;

		if (info->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
			dir->dirent.stat.mode = S_IFLNK;
			dir->dirent.stat.rdev = info->EaSize;
		} else if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			dir->dirent.stat.mode = S_IFDIR;
		else
			dir->dirent.stat.mode = S_IFREG;

		if (dir->level == FileBothDirectoryInformation || dir->level == FileIdBothDirectoryInformation) {
			FILE_BOTH_DIR_INFORMATION *both_info = (FILE_BOTH_DIR_INFORMATION *)info;
			u32 short_name_len = both_info->ShortNameLength / sizeof(WCHAR);
			if (short_name_len)
				dir->dirent.short_name = pcs_utf16_to_utf8(both_info->ShortName, short_name_len);
		}
		return 1;
	}
	return 0;
}

__must_check int pcs_dirent_next(pcs_dirent_t *dirent)
{
	struct pcs_dirent_priv *dir = container_of(dirent, struct pcs_dirent_priv, dirent);

	for (;;) {
		int rc = __dirent_next(dir);
		if (rc)
			return rc;

		IO_STATUS_BLOCK iosb;
		NTSTATUS status = NtQueryDirectoryFilePtr(dir->handle, NULL, NULL, NULL, &iosb, dir->buffer, sizeof(dir->buffer), dir->level, FALSE, NULL, FALSE);
		if (status == STATUS_NO_MORE_FILES)
			return 0;
		if (status != STATUS_SUCCESS)
			return -(int)RtlNtStatusToDosErrorPtr(status);
		dir->pos = 0;
		dir->size = (u32)iosb.Information;
	}
}

void pcs_dirent_close(pcs_dirent_t *dirent)
{
	struct pcs_dirent_priv *dir = container_of(dirent, struct pcs_dirent_priv, dirent);

	pcs_sync_close(dir->handle);
	pcs_free(dir->dirent.name);
	pcs_free(dir->dirent.short_name);
	pcs_free(dir);
}

struct _co_req_dirent_first {
	const char	*path;
	u32		flags;
	pcs_dirent_t	*out_dir;
};

static int _co_sync_dirent_first(void *arg)
{
	struct _co_req_dirent_first *req = arg;
	return pcs_dirent_first(req->path, req->flags, &req->out_dir);
}

/*
pcs_co_dirent_next() is made compatible with pcs_dirent_t returned by pcs_dirent_first()
on _Windows_

This is done to make possible to call pcs_dirent_first() from impersonated thread
and then later use generic pcs_co_dirent_next() for subsequent invocations using
the same pcs_dirent_t instance.

NB! Linux and Mac iterators are not affected by this change and should not be mixed.

*/
__must_check int pcs_co_dirent_first(const char *path, u32 flags, pcs_dirent_t **out_dir)
{
	struct _co_req_dirent_first req = {.path = path, .flags = flags};
	int rc = pcs_co_filejob(pcs_current_proc->co_io, _co_sync_dirent_first, &req);
	if (rc >= 0)
		*out_dir = req.out_dir;
	return rc;
}

__must_check int pcs_co_dirent_firstat(pcs_fd_t dirfd, const char *path, u32 flags, pcs_dirent_t **out_dir)
{
	BUG(); // not implemented for Windows
}

static int _co_sync_dirent_next(void *dir)
{
	return pcs_dirent_next(dir);
}

__must_check int pcs_co_dirent_next(pcs_dirent_t *dirent)
{
	struct pcs_dirent_priv *dir = container_of(dirent, struct pcs_dirent_priv, dirent);
	int rc = __dirent_next(dir);
	if (rc)
		return rc;
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_dirent_next, &dir->dirent);
}

static int _co_sync_dirent_close(void *arg)
{
	struct pcs_dirent_priv *priv = arg;
	return pcs_sync_close(priv->handle);
}

void pcs_co_dirent_close(pcs_dirent_t *dirent)
{
	if (!dirent)
		return;

	struct pcs_dirent_priv *dir = container_of(dirent, struct pcs_dirent_priv, dirent);
	pcs_co_filejob(pcs_current_proc->co_io, _co_sync_dirent_close, dir);
	pcs_free(dir->dirent.name);
	pcs_free(dir->dirent.short_name);
	pcs_free(dir);
}

#else /* !__WINDOWS__ */

#define IS_DOT_OR_DOT_DOT(x) (x[0] == '.' && (x[1] == 0 || (x[1] == '.' && x[2] == 0)))

struct pcs_dirent_priv {
	struct pcs_dirent	dirent;
	DIR			*dir;
	u32			flags;
};

static __must_check int __dirent_first(DIR* dir, u32 flags, pcs_dirent_t **out_dir)
{
	int err;
	struct pcs_dirent_priv *dirent = pcs_xzmalloc(sizeof(*dirent));

	dirent->flags = flags;
	dirent->dir = dir;

	if ((err = pcs_dirent_next(&dirent->dirent)) < 0) {
		pcs_dirent_close(&dirent->dirent);
		return err;
	}

	*out_dir = &dirent->dirent;
	return err;
}

__must_check int pcs_dirent_first(const char *path, u32 flags, pcs_dirent_t **out_dir)
{
	DIR *dir = opendir(path);
	if (!dir)
		return -errno;
	return __dirent_first(dir, flags, out_dir);
}

#if defined(__linux__) && !__GLIBC_PREREQ(2, 4)
#define USE_OPENAT_EMULATION

typedef DIR *(*fdopendir_t)(int fd);

static pthread_once_t _fdopendir_once = PTHREAD_ONCE_INIT;
static fdopendir_t _fdopendir_func = NULL;

static void _fdopendir_init(void)
{
	static const char func_name[] = "fdopendir";
	void* sym = dlsym(RTLD_DEFAULT, func_name);
	if (!sym) {
		pcs_log(LOG_TRACE, "'%s' not found in glibc. Cause: %s.", func_name, dlerror());
		return;
	}
	_fdopendir_func = (fdopendir_t)sym;
}

static DIR *fdopendir(pcs_fd_t fd)
{
	BUG_ON(fd < 0);
	return _fdopendir_func(fd);
}

static inline int _fdopendir_available(void)
{
	pthread_once(&_fdopendir_once, _fdopendir_init);
	return _fdopendir_func != NULL;
}
#endif /* defined(__linux__) && !__GLIBC_PREREQ(2, 4) */

__must_check int pcs_dirent_firstat(pcs_fd_t dirfd, const char *pathname, u32 flags, pcs_dirent_t **out_dir)
{
	int rc;
	DIR *dir = NULL;
#ifdef USE_OPENAT_EMULATION
	if (!_fdopendir_available()) {
		char *path = pcs_pathat(dirfd, pathname);
		dir = opendir(path);
		rc = dir ? 0 : -errno;
		pcs_free(path);
		if (!dir)
			return rc;

		return __dirent_first(dir, flags, out_dir);
	}
#endif /* USE_OPENAT_EMULATION */
	pcs_fd_t fd = PCS_INVALID_FD;
	const int openat_flags = O_RDONLY | O_CLOEXEC | O_DIRECTORY;
	if ((rc = pcs_sync_openat(dirfd, pathname, openat_flags, 0, &fd)))
		return rc;
	dir = fdopendir(fd);
	if (!dir) {
		rc = -errno;
		pcs_sync_close(fd);
		return rc;
	}

	return __dirent_first(dir, flags, out_dir);
}

__must_check int pcs_dirent_next(pcs_dirent_t *dirent)
{
	struct pcs_dirent_priv *dir = container_of(dirent, struct pcs_dirent_priv, dirent);
	for (;;) {
		errno = 0;
		struct dirent *entry = readdir(dir->dir);
		if (!entry) {
			dir->dirent.name = NULL;
			return -errno;
		}
		if (IS_DOT_OR_DOT_DOT(entry->d_name))
			continue;

		if (dir->flags & PCS_DIRENT_STAT) {
			int rc;
			if ((rc = pcs_sync_fstatat(dirfd(dir->dir), entry->d_name, &dir->dirent.stat))) {
				if (-rc == ENOENT)
					continue;
				dir->dirent.name = NULL;
				return rc;
			}
		} else {
#ifndef __SUN__
			dir->dirent.stat.mode = DTTOIF(entry->d_type);
#endif
			dir->dirent.stat.ino = entry->d_ino;
		}
		dir->dirent.name = entry->d_name;
		return 1;
	}
}

void pcs_dirent_close(pcs_dirent_t *dirent)
{
	if (!dirent)
		return;

	struct pcs_dirent_priv *dir = container_of(dirent, struct pcs_dirent_priv, dirent);
	closedir(dir->dir);
	pcs_free(dir);
}

#define CO_CACHED_DIRENTS_NR (64)

struct pcs_dirent_cached {
	struct pcs_dirent	dirent[CO_CACHED_DIRENTS_NR];
	pcs_dirent_t		*original;
	u32			current;
	u32			total;
	int			ret_code;
};

static int _co_sync_dirent_next(void *arg)
{
	struct pcs_dirent_cached *dir = arg;
	int r;

	for (;;) {
		r = pcs_dirent_next(dir->original);
		if (r <= 0) {
			pcs_dirent_close(dir->original);
			dir->original = NULL;
			break;
		}
		if (++dir->total > CO_CACHED_DIRENTS_NR)
			break;
		dir->dirent[dir->total - 1].name = pcs_xstrdup(dir->original->name);
		dir->dirent[dir->total - 1].short_name = NULL;
		dir->dirent[dir->total - 1].stat = dir->original->stat;
	}
	dir->ret_code = r;
	if (dir->total)
		return 1;
	dir->dirent[0].name = NULL;
	return 0;
}

struct _co_req_dirent_first {
	int			dirfd;
	const char		*path;
	u32			flags;
	pcs_dirent_t		**out_dir;
};

static int _co_sync_dirent_first(void *arg)
{
	struct _co_req_dirent_first *req = arg;
	struct pcs_dirent_cached *dir = pcs_xmalloc(sizeof(*dir));

	int r = req->dirfd == PCS_INVALID_FD ?
			pcs_dirent_first(req->path, req->flags, &dir->original) :
			pcs_dirent_firstat(req->dirfd, req->path, req->flags, &dir->original);
	if (r < 0) {
		pcs_free(dir);
		return r;
	}

	*req->out_dir = dir->dirent;
	dir->current = 0;

	if (r == 0) {
		memset(dir->dirent, 0, sizeof(dir->dirent[0]));
		pcs_dirent_close(dir->original);
		dir->original = NULL;
		dir->total = 0;
		dir->ret_code = 0;
		return 0;
	}

	dir->total = 1;
	dir->dirent[0].name = pcs_xstrdup(dir->original->name);
	dir->dirent[0].short_name = NULL;
	dir->dirent[0].stat = dir->original->stat;
	return _co_sync_dirent_next(dir);
}

__must_check int pcs_co_dirent_first(const char *path, u32 flags, pcs_dirent_t **out_dir)
{
	return pcs_co_dirent_firstat(PCS_INVALID_FD, path, flags, out_dir);
}

__must_check int pcs_co_dirent_firstat(pcs_fd_t dirfd, const char *path, u32 flags, pcs_dirent_t **out_dir)
{
	struct _co_req_dirent_first req = {
		.dirfd = dirfd,
		.path = path,
		.flags = flags,
		.out_dir = out_dir,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_dirent_first, &req);
}

__must_check int pcs_co_dirent_next(pcs_dirent_t *dirent)
{
	struct pcs_dirent_cached *dir = container_of(dirent, struct pcs_dirent_cached, dirent[0]);

	if (dir->current < dir->total) {
		if (dir->current < CO_CACHED_DIRENTS_NR)
			pcs_free(dir->dirent[dir->current].name);
		dir->current++;
	}

	if (dir->current < dir->total) {
		if (dir->current < CO_CACHED_DIRENTS_NR)
			dir->dirent[0] = dir->dirent[dir->current];
		else
			dir->dirent[0] = *dir->original;
		return 1;
	}

	if (dir->ret_code <= 0) {
		dir->dirent[0].name = NULL;
		return dir->ret_code;
	}

	dir->current = 0;
	dir->total = 0;
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_dirent_next, dir);
}

static int _co_sync_dirent_close(void *dir)
{
	pcs_dirent_close(dir);
	return 0;
}

void pcs_co_dirent_close(pcs_dirent_t *dirent)
{
	if (!dirent)
		return;

	struct pcs_dirent_cached *dir = container_of(dirent, struct pcs_dirent_cached, dirent[0]);

	while (dir->current < dir->total && dir->current < CO_CACHED_DIRENTS_NR)
		pcs_free(dir->dirent[dir->current++].name);
	if (dir->original)
		pcs_co_filejob(pcs_current_proc->co_io, _co_sync_dirent_close, dir->original);
	pcs_free(dir);
}

#endif /* !__WINDOWS__ */
