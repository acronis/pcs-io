/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_co_io.h"
#include "pcs_co_locks.h"
#include "pcs_context.h"
#include "pcs_fd_gc.h"
#include "pcs_iocp.h"
#include "pcs_process.h"
#include "pcs_sync_io.h"
#include "pcs_file_job.h"
#include "pcs_malloc.h"
#include "pcs_compat.h"
#include "log.h"
#include "bug.h"

#ifndef __WINDOWS__
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <netinet/in.h>
#else /* __WINDOWS__ */
#include <io.h>
#include <stdio.h>
#include "pcs_winapi.h"
#endif

static const struct pcs_co_file_ops pcs_co_file_ops;
static const struct pcs_co_file_ops pcs_co_sock_ops;
static const struct pcs_co_file_ops pcs_co_file_with_preadv_ops;
static const struct pcs_co_file_ops pcs_co_dummy_ops;
static struct pcs_co_file *pcs_co_file_alloc(pcs_fd_t fd, const struct pcs_co_file_ops *ops);
static struct pcs_co_file *pcs_co_file_alloc_dummy(pcs_fd_t fd);

/* -------------------------------------------------------------------------------------------------- */

static pcs_sock_t pcs_new_socket(int family, int type)
{
#ifdef SOCK_CLOEXEC
	return socket(family, type | SOCK_CLOEXEC, 0);
#elif defined(__WINDOWS__) || defined(__MAC__)
	/* On Mac we use POSIX_SPAWN_CLOEXEC_DEFAULT and do not care about CLOEXEC state */
	return socket(family, type, 0);
#else
	struct pcs_co_rwlock *lock = pcs_current_proc->exec_lock;
	pcs_co_read_lock(lock);
	pcs_sock_t fd = socket(family, type, 0);
	if (fd >= 0)
		fcntl(fd, F_SETFD, FD_CLOEXEC);
	pcs_co_read_unlock(lock);
	return fd;
#endif
}

/* -------------------------------------------------------------------------------------------------- */

#ifndef __WINDOWS__

int pcs_co_file_pipe(struct pcs_co_file ** in_file, struct pcs_co_file ** out_file)
{
	int pfd[2];

#ifdef HAVE_PIPE2
	if (pipe2(pfd, O_CLOEXEC))
		return -errno;
#elif defined(__MAC__)
	/* On Mac we use POSIX_SPAWN_CLOEXEC_DEFAULT and do not care about CLOEXEC state */
	if (pipe(pfd))
		return -errno;
#else
	struct pcs_co_rwlock *lock = pcs_current_proc->exec_lock;
	pcs_co_read_lock(lock);
	if (pipe(pfd)) {
		int rc = -errno;
		pcs_co_read_unlock(lock);
		return rc;
	}
	fcntl(pfd[0], F_SETFD, FD_CLOEXEC);
	fcntl(pfd[1], F_SETFD, FD_CLOEXEC);
	pcs_co_read_unlock(lock);
#endif

	*in_file = pcs_co_file_alloc_socket(pfd[0]);
	*out_file = pcs_co_file_alloc_socket(pfd[1]);
	return 0;
}

int pcs_co_file_pipe_ex(struct pcs_co_file ** in_file, struct pcs_co_file ** out_file, int pipe_for_exec)
{
	int pfd[2];

#ifdef HAVE_PIPE2
	if (pipe2(pfd, O_CLOEXEC))
		return -errno;
#elif defined(__MAC__)
	/* On Mac we use POSIX_SPAWN_CLOEXEC_DEFAULT and do not care about CLOEXEC state */
	if (pipe(pfd))
		return -errno;
#else
	BUG_ON(!pcs_co_is_write_locked(pcs_current_proc->exec_lock));

	if (pipe(pfd))
		return -errno;

	fcntl(pfd[0], F_SETFD, FD_CLOEXEC);
	fcntl(pfd[1], F_SETFD, FD_CLOEXEC);
#endif

	*in_file = (pipe_for_exec == PCS_CO_IN_PIPE_FOR_EXEC) ? pcs_co_file_alloc_dummy(pfd[0]) : pcs_co_file_alloc_socket(pfd[0]);
	*out_file = (pipe_for_exec == PCS_CO_OUT_PIPE_FOR_EXEC) ? pcs_co_file_alloc_dummy(pfd[1]) : pcs_co_file_alloc_socket(pfd[1]);
	return 0;
}

int pcs_co_open_dev_null(int flags, struct pcs_co_file ** file)
{
	int fd, rc;

	if ((rc = pcs_sync_open("/dev/null", flags, 0, &fd)))
		return rc;

	*file = pcs_co_file_alloc_dummy(fd);
	return 0;
}

/* -------------------------------------------------------------------------------------------------- */

#if defined(__LINUX__)

#if !__GLIBC_PREREQ(2, 10)

#if defined(__i386__)
#define SYS_preadv 333
#define SYS_pwritev 334
#elif defined(__x86_64__)
#define SYS_preadv 295
#define SYS_pwritev 296
#else
#error "unsupported architecture"
#endif

static inline ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
	return syscall(SYS_preadv, fd, iov, iovcnt, offset);
}

static inline ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
	return syscall(SYS_pwritev, fd, iov, iovcnt, offset);
}

#endif

static int pcs_preadv_supported(int flag)
{
	int ret = syscall(SYS_preadv, -1, NULL, 0, (off_t)0);
	return !(ret == -1 && errno == ENOSYS);
}

struct _co_iov_req_rw
{
	pcs_fd_t fd;
	u64 offset;

	int iovcnt;
	const struct iovec *iov;
};

static int _co_file_job_readv(void *arg)
{
	struct _co_iov_req_rw *req = (struct _co_iov_req_rw *)arg;
	const struct iovec *iov = req->iov;
	int iovcnt = req->iovcnt;
	int result = 0;
	int rc, i, size;

	while (iovcnt > IOV_MAX) {
		for (size = 0, i = 0; i < IOV_MAX; i++)
			size += iov[i].iov_len;

		rc = preadv(req->fd, iov, IOV_MAX, req->offset + result);
		if (rc != size)
			goto done;

		result += rc;
		iov += IOV_MAX;
		iovcnt -= IOV_MAX;
	}

	rc = preadv(req->fd, iov, iovcnt, req->offset + result);

done:
	if (rc < 0)
		return -errno;
	return result + rc;
}

static int pcs_co_sync_readv(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u64 offset, u32 flags)
{
	struct _co_iov_req_rw req = {
		.fd = pcs_co_file_fd(file),
		.iovcnt = iovcnt,
		.iov = iov,
		.offset = offset,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_file_job_readv, &req);
}

static int _co_file_job_writev(void *arg)
{
	struct _co_iov_req_rw *req = (struct _co_iov_req_rw *)arg;
	const struct iovec *iov = req->iov;
	int iovcnt = req->iovcnt;
	int result = 0;
	int rc, i, size;

	while (iovcnt > IOV_MAX) {
		for (size = 0, i = 0; i < IOV_MAX; i++)
			size += iov[i].iov_len;

		rc = pwritev(req->fd, iov, IOV_MAX, req->offset + result);
		if (rc != size)
			goto done;

		result += rc;
		iov += IOV_MAX;
		iovcnt -= IOV_MAX;
	}

	rc = pwritev(req->fd, iov, iovcnt, req->offset + result);

done:
	if (rc < 0)
		return -errno;
	return result + rc;
}

static int pcs_co_sync_writev(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u64 offset, u32 flags)
{
	struct _co_iov_req_rw req = {
		.fd = pcs_co_file_fd(file),
		.iovcnt = iovcnt,
		.iov = iov,
		.offset = offset,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_file_job_writev, &req);
}

#elif defined(__MAC__)

struct _co_iov_req_rw
{
	struct pcs_co_file *file;
	u64 offset;

	int iovcnt;
	const struct iovec *iov;
};

static int _co_file_job_writev(void *arg)
{
	struct _co_iov_req_rw *req = (struct _co_iov_req_rw *)arg;
	struct pcs_co_file *file = req->file;
	int fd = pcs_co_file_fd(file);
	const struct iovec *iov = req->iov;
	int iovcnt = req->iovcnt;
	u64 offset = req->offset;
	int result = 0;
	int rc, i, size;

	if (file->wr_offs != offset && (rc = pcs_sync_lseek(fd, offset, SEEK_SET, &file->wr_offs)))
		return rc;

	while (iovcnt > IOV_MAX) {
		for (size = 0, i = 0; i < IOV_MAX; i++)
			size += iov[i].iov_len;

		rc = writev(fd, iov, IOV_MAX);
		if (rc != size)
			goto done;

		result += rc;
		iov += IOV_MAX;
		iovcnt -= IOV_MAX;
		file->wr_offs += rc;
	}

	rc = writev(fd, iov, iovcnt);

done:
	if (rc < 0)
		return -errno;

	file->wr_offs += rc;
	return result + rc;
}

static int pcs_co_sync_writev(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u64 offset, u32 flags)
{
	struct _co_iov_req_rw req = {
		.file = file,
		.iovcnt = iovcnt,
		.iov = iov,
		.offset = offset,
	};
	pcs_co_mutex_lock(&file->wr_mutex);
	int rc = pcs_co_filejob(pcs_current_proc->co_io, _co_file_job_writev, &req);
	pcs_co_mutex_unlock(&file->wr_mutex);
	return rc;
}

static int pcs_preadv_supported(int flag)
{
	return 1;
}

#else /* !__LINUX__ && !__MAC__ */

static int pcs_preadv_supported(int flag)
{
	return 0;
}

#endif /* __LINUX__ */

/* -------------------------------------------------------------------------------------------------- */

struct _co_io_req_fstatvfs
{
	pcs_fd_t fd;
	struct pcs_statvfs * res;
};

static int _co_sync_io_fstatvfs(void * arg)
{
	struct _co_io_req_fstatvfs * req = arg;
	return pcs_sync_fstatvfs(req->fd, req->res);
}

int pcs_co_fstatvfs(pcs_fd_t fd, struct pcs_statvfs * res)
{
	struct _co_io_req_fstatvfs req = {
		.fd = fd,
		.res = res,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_fstatvfs, &req);
}

/* -------------------------------------------------------------------------------------------------- */

static inline int poll_error_mask(struct pcs_co_file *file)
{
#ifdef HAVE_EPOLL
	return pcs_atomic32_load(&file->err_mask);
#else
	return 0;
#endif
}

static int pcs_co_nb_read(struct pcs_co_file *file, void * buf, int size, u64 offset, u32 flags)
{
	int err;

	if (!size)
		return 0;

	if (flags & CO_IO_NOWAIT) {
		/* Call can be made from any thread, do not use coroutine functions */
		int n = read(pcs_co_file_fd(file), buf, size);
		if (n >= 0)
			return n;
		err = -errno;
		if (err != -EINTR && err != -EAGAIN)
			return err;
		return 0;
	}

	int total = 0;
	for (;;) {
		if ((err = pcs_cancelable_prepare_wait(&file->reader, pcs_current_co->ctx)))
			return err;

		int n = read(pcs_co_file_fd(file), buf, size);
		if (n == 0)
			break;

		if (n > 0) {
			size -= n;
			buf = (char*)buf + n;
			total += n;
			if (size == 0 || (flags & CO_IO_PARTIAL))
				break;

			if (poll_error_mask(file) & (POLLRDHUP|POLLHUP|POLLERR|POLLNVAL))
				continue;
		} else {
			err = -errno;
			if (err == -EINTR)
				continue;
			if (err != -EAGAIN)
				return err;
		}

		pcs_poll_file_begin(file, POLLIN);
		pcs_co_event_wait(&file->reader.ev);
	}
	return total;
}

static int pcs_co_nb_write(struct pcs_co_file *file, const void * buf, int size, u64 offset, u32 flags)
{
	int err;

	if (!size)
		return 0;

	if (flags & CO_IO_NOWAIT) {
		/* Call can be made from any thread, do not use coroutine functions */
		int n = write(pcs_co_file_fd(file), buf, size);
		BUG_ON(n == 0);
		if (n > 0)
			return n;
		err = -errno;
		if (err != -EINTR && err != -EAGAIN)
			return err;
		return 0;
	}

	int total = 0;
	for (;;) {
		if ((err = pcs_cancelable_prepare_wait(&file->writer, pcs_current_co->ctx)))
			return err;

		int n = write(pcs_co_file_fd(file), buf, size);
		BUG_ON(n == 0);

		if (n > 0) {
			size -= n;
			buf = (char*)buf + n;
			total += n;
			if (size == 0 || (flags & CO_IO_PARTIAL))
				break;

			if (poll_error_mask(file) & (POLLHUP|POLLERR|POLLNVAL))
				continue;
		} else {
			err = -errno;
			if (err == -EINTR)
				continue;
			if (err != -EAGAIN)
				return err;
		}

		pcs_poll_file_begin(file, POLLOUT);
		pcs_co_event_wait(&file->writer.ev);
	}
	return total;
}

static int pcs_co_nb_readv(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u64 offset, u32 flags)
{
	int err;

	if (flags & CO_IO_NOWAIT) {
		/* Call can be made from any thread, do not use coroutine functions */
		int n = readv(pcs_co_file_fd(file), iov, iovcnt);
		if (n >= 0)
			return n;
		err = -errno;
		if (err != -EINTR && err != -EAGAIN)
			return err;
		return 0;
	}

	int total = 0;
	int skip = 0;
	for (;;) {
		if ((err = pcs_cancelable_prepare_wait(&file->reader, pcs_current_co->ctx)))
			return err;

		int n;
		if (skip) {
			struct iovec save_iov = *iov;
			iov->iov_base += skip;
			iov->iov_len -= skip;
			n = readv(pcs_co_file_fd(file), iov, iovcnt);
			*iov = save_iov;
		} else {
			n = readv(pcs_co_file_fd(file), iov, iovcnt);
		}
		if (n == 0)
			break;

		if (n > 0) {
			total += n;
			if (flags & CO_IO_PARTIAL)
				break;
			n += skip;
			while (iovcnt && n >= iov->iov_len) {
				n -= iov->iov_len;
				iov++;
				iovcnt--;
			}
			if (iovcnt == 0)
				break;

			skip = n;
			if (poll_error_mask(file) & (POLLRDHUP|POLLHUP|POLLERR|POLLNVAL))
				continue;
		} else {
			err = -errno;
			if (err == -EINTR)
				continue;
			if (err != -EAGAIN)
				return err;
		}

		pcs_poll_file_begin(file, POLLIN);
		pcs_co_event_wait(&file->reader.ev);
	}
	return total;
}

static int pcs_co_nb_writev(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u64 offset, u32 flags)
{
	int err;

	if (flags & CO_IO_NOWAIT) {
		/* Call can be made from any thread, do not use coroutine functions */
		int n = writev(pcs_co_file_fd(file), iov, iovcnt);
		BUG_ON(n == 0);
		if (n > 0)
			return n;
		err = -errno;
		if (err != -EINTR && err != -EAGAIN)
			return err;
		return 0;
	}

	int total = 0;
	int skip = 0;
	for (;;) {
		if ((err = pcs_cancelable_prepare_wait(&file->writer, pcs_current_co->ctx)))
			return err;

		int n;
		if (skip) {
			struct iovec save_iov = *iov;
			iov->iov_base += skip;
			iov->iov_len -= skip;
			n = writev(pcs_co_file_fd(file), iov, iovcnt);
			*iov = save_iov;
		} else {
			n = writev(pcs_co_file_fd(file), iov, iovcnt);
		}
		if (n == 0) {
			while (iovcnt && !iov->iov_len) {
				iov++;
				iovcnt--;
			}
			BUG_ON(iovcnt);
			break;
		}

		if (n > 0) {
			total += n;
			if (flags & CO_IO_PARTIAL)
				break;
			n += skip;
			while (iovcnt && n >= iov->iov_len) {
				n -= iov->iov_len;
				iov++;
				iovcnt--;
			}
			if (iovcnt == 0)
				break;

			skip = n;
			if (poll_error_mask(file) & (POLLHUP|POLLERR|POLLNVAL))
				continue;
		} else {
			err = -errno;
			if (err == -EINTR)
				continue;
			if (err != -EAGAIN)
				return err;
		}

		pcs_poll_file_begin(file, POLLOUT);
		pcs_co_event_wait(&file->writer.ev);
	}
	return total;
}

/* -------------------------------------------------------------------------------------------------- */

static int pcs_co_connect_sa(struct sockaddr * sa, unsigned int sa_len, struct pcs_co_file ** file_out)
{
	int fd, err;

	while ((fd = pcs_new_socket(sa->sa_family, SOCK_STREAM)) < 0) {
		err = errno;
		if (pcs_fd_gc_on_error(pcs_current_proc, err, 1) <= 0)
			return -err;
	}

	pcs_sock_keepalive(fd);
	if (pcs_sock_cork(fd) < 0)
		pcs_sock_nodelay(fd);

	struct pcs_co_file *file = pcs_co_file_alloc_socket(fd);
	int connect_called = 0;

	for (;;) {
		if ((err = pcs_cancelable_prepare_wait(&file->writer, pcs_current_co->ctx)))
			break;

		if (!connect_called) {
			connect_called = 1;
			err = connect(fd, sa, sa_len) ? -errno : 0;
		} else {
			socklen_t so_len = sizeof(err);
			if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &so_len))
				err = -EINVAL;
			else
				err = -err;	/* getsockopt() returns a positive error code */
		}

		if (!err) {
			*file_out = file;
			return 0;
		}

		if (err != -EINPROGRESS)
			break;

		pcs_poll_file_begin(file, POLLOUT);
		pcs_co_event_wait(&file->writer.ev);
	}

	pcs_co_file_close(file);
	return err;
}

static int pcs_co_accept_sa(struct pcs_co_file * listen, struct sockaddr * sa, unsigned int * sa_len,
			    struct pcs_co_file ** file_out)
{
	int fd;

	for (;;) {
		int err;
		if ((err = pcs_cancelable_prepare_wait(&listen->reader, pcs_current_co->ctx)))
			return err;

#ifdef HAVE_ACCEPT4
		fd = accept4(pcs_co_file_sock(listen), sa, sa_len, SOCK_CLOEXEC);
#elif defined(__MAC__)
		fd = accept(pcs_co_file_sock(listen), sa, sa_len);
#else
		struct pcs_co_rwlock *lock = pcs_current_proc->exec_lock;
		pcs_co_read_lock(lock);
		fd = accept(pcs_co_file_sock(listen), sa, sa_len);
		if (fd >= 0)
			fcntl(fd, F_SETFD, FD_CLOEXEC);
		pcs_co_read_unlock(lock);
#endif
		if (fd >= 0)
			break;

		err = errno;
		if (err == EINTR)
			continue;

		if (err != EAGAIN) {
			if (pcs_fd_gc_on_error(pcs_current_proc, err, PCS_GC_FD_ON_ACCEPT) <= 0)
				return -err;

			continue;
		}

		pcs_poll_file_begin(listen, POLLIN);
		pcs_co_event_wait(&listen->reader.ev);
	}

	pcs_sock_keepalive(fd);
	if (pcs_sock_cork(fd) < 0)
		pcs_sock_nodelay(fd);

	*file_out = pcs_co_file_alloc_socket(fd);
	return 0;
}

/* -------------------------------------------------------------------------------------------------- */

struct _co_io_req_rw
{
	pcs_fd_t fd;
	void * buf;
	int size;
	u64 offset;
};

static int _co_sync_io_read(void * arg)
{
	struct _co_io_req_rw * req = arg;
	return pcs_sync_nread(req->fd, req->offset, req->buf, req->size);
}

static int pcs_co_sync_read(struct pcs_co_file *file, void * buf, int size, u64 offset, u32 flags)
{
	struct _co_io_req_rw req = {
		.fd = pcs_co_file_fd(file),
		.buf = buf,
		.size = size,
		.offset = offset,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_read, &req);
}

#ifdef __MAC__
struct _co_io_req_wr
{
	struct pcs_co_file *file;
	void *buf;
	int size;
	u64 offset;
};

static int _co_sync_io_write(void *arg)
{
	struct _co_io_req_wr *req = arg;
	struct pcs_co_file *file = req->file;
	u64 offset = req->offset;
	int fd = pcs_co_file_fd(file);
	int rc;

	if (file->wr_offs != offset && (rc = pcs_sync_lseek(fd, offset, SEEK_SET, &file->wr_offs)))
		return rc;
	if ((rc = pcs_sync_swrite(fd, req->buf, req->size)))
		return rc;

	file->wr_offs += req->size;
	return 0;
}

static int pcs_co_sync_write(struct pcs_co_file *file, const void *buf, int size, u64 offset, u32 flags)
{
	struct _co_io_req_wr req = {
		.file = file,
		.buf = (void *)buf,
		.size = size,
		.offset = offset,
	};
	pcs_co_mutex_lock(&file->wr_mutex);
	int rc = pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_write, &req);
	pcs_co_mutex_unlock(&file->wr_mutex);
	return rc;
}
#else /* !__MAC__ */
static int _co_sync_io_write(void * arg)
{
	struct _co_io_req_rw * req = arg;
	return pcs_sync_nwrite(req->fd, req->offset, req->buf, req->size);
}

static int pcs_co_sync_write(struct pcs_co_file *file, const void * buf, int size, u64 offset, u32 flags)
{
	struct _co_io_req_rw req = {
		.fd = pcs_co_file_fd(file),
		.buf = (void *)buf,
		.size = size,
		.offset = offset,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_write, &req);
}
#endif /* !__MAC__ */

/* -------------------------------------------------------------------------------------------------- */

static int pcs_co_sync_close(struct pcs_co_file *file)
{
	/* close() can block on NFS or vstorage... */
	int rc = pcs_co_file_close_fd(pcs_co_file_fd(file));
	pcs_free(file);
	return rc;
}

static int pcs_dummy_close(struct pcs_co_file *file)
{
	int rc = pcs_sync_close(pcs_co_file_fd(file));
	pcs_free(file);
	return rc;
}

/* When epoll is running in multiple threads, it is possible that file is closed
 * before already recieved event for the file was processed in another thread.
 * We want to handle this race without added synchronization overhead.
 * We solve the problem by never freeing struct pcs_co_file.
 * In the worst case we can get spurious wakeup of the coroutine performing I/O
 * on the reused struct pcs_co_file, which is handled properly. */
static struct pcs_co_file *__pcs_co_file_get_from_pool(void)
{
	struct pcs_process *proc = pcs_current_proc;

	struct pcs_co_file *file = pcs_atomic_ptr_load(&proc->co_file_pool);
	for (;;) {
		if (!file) {
			file = pcs_xzmalloc(sizeof(*file));
#ifdef __SUN__
			pthread_mutex_init(&file->mutex, NULL);
#endif
			break;
		}

		void *next = pcs_atomic_ptr_load(&file->next);
		void *res = pcs_atomic_ptr_cas(&proc->co_file_pool, file, next);
		if (res == file)
			break;

		file = res;
	}
	return file;
}

static void __pcs_co_file_put_to_pool(struct pcs_co_file *file)
{
	struct pcs_process *proc = pcs_current_proc;

	void* head = pcs_atomic_ptr_load(&proc->co_file_pool);
	for (;;) {
		pcs_atomic_ptr_store(&file->next, head);
		void *res = pcs_atomic_ptr_cas(&proc->co_file_pool, head, file);
		if (res == head)
			break;
		head = res;
	}
}

static int pcs_co_nb_close(struct pcs_co_file *file)
{
	pcs_poll_file_fini(file);
	pcs_cancelable_prepare_wait(&file->reader, NULL);
	pcs_cancelable_prepare_wait(&file->writer, NULL);

	close(file->fd);
	file->fd = -1;

	__pcs_co_file_put_to_pool(file);
	return 0;
}


struct pcs_co_file *pcs_co_file_alloc_socket(pcs_sock_t sock)
{
	pcs_sock_nonblock(sock);

	struct pcs_co_file *file = __pcs_co_file_get_from_pool();

	file->ops = &pcs_co_sock_ops;
	file->fd = sock;
	file->priv = NULL;

	pcs_poll_file_init(file);
	return file;
}

void pcs_co_file_pool_free(struct pcs_process *proc)
{
	/* Code is executed on process stop and does not have to be thread-safe */
	struct pcs_co_file *f = pcs_atomic_ptr_load(&proc->co_file_pool);
	while (f) {
		struct pcs_co_file *next = pcs_atomic_ptr_load(&f->next);
#ifdef __SUN__
		pthread_mutex_destroy(&f->mutex);
#endif
		pcs_free(f);
		f = next;
	}
}

/* -------------------------------------------------------------------------------------------------- */

#else /* __WINDOWS__ */

/* -------------------------------------------------------------------------------------------------- */

static void disable_notifications(struct pcs_co_file *file, u8 skip_sync_notify)
{
	if (!SetFileCompletionNotificationModesPtr)
		return;

	UCHAR flags = FILE_SKIP_SET_EVENT_ON_HANDLE;
	if (skip_sync_notify)
		flags |= FILE_SKIP_COMPLETION_PORT_ON_SUCCESS;

	BOOL ok = SetFileCompletionNotificationModesPtr(pcs_co_file_fd(file), flags);
	if (ok && skip_sync_notify)
		file->skip_sync_notify = 1;
}

/* -------------------------------------------------------------------------------------------------- */

int pcs_co_file_pipe(struct pcs_co_file ** in_file, struct pcs_co_file ** out_file)
{
	return pcs_co_file_pipe_ex(in_file, out_file, 0);
}

int pcs_co_file_pipe_ex(struct pcs_co_file ** in_file, struct pcs_co_file ** out_file, int pipe_for_exec)
{
	/* https://msdn.microsoft.com/en-us/library/windows/desktop/aa365141(v=vs.85).aspx
	   Windows anonymous pipes cannot be used with overlapped operations.
	   This helper function creates pipe with FILE_FLAG_OVERLAPPED set and unique name.
	   Returns TRUE on success and sets read and write handles as POSIX pipe() */
	const DWORD PipeBufferSize = 4096;
	const DWORD PipeTimeout = 120 * 1000;
	static long PipeSerialNumber;
	HANDLE ReadPipeHandle, WritePipeHandle;
	DWORD dwError;
	char PipeNameBuffer[MAX_PATH];

	sprintf(PipeNameBuffer,
		"\\\\.\\Pipe\\RemoteExeAnon.%08x.%08x",
		GetCurrentProcessId(),
		PipeSerialNumber++
		);

	SECURITY_ATTRIBUTES ReadPipeAttr = {
		.nLength		= sizeof(ReadPipeAttr),
		.lpSecurityDescriptor	= NULL,
		.bInheritHandle		= (pipe_for_exec == PCS_CO_IN_PIPE_FOR_EXEC),
	};

	ReadPipeHandle = CreateNamedPipeA(
		PipeNameBuffer,
		PIPE_ACCESS_INBOUND | (pipe_for_exec == PCS_CO_IN_PIPE_FOR_EXEC ? 0 : FILE_FLAG_OVERLAPPED),
		PIPE_TYPE_BYTE | PIPE_WAIT,
		1,              // Number of pipes
		PipeBufferSize, // Out buffer size
		PipeBufferSize, // In buffer size
		PipeTimeout,    // Timeout in ms
		&ReadPipeAttr   // Pipe attributes
		);

	if (!ReadPipeHandle) {
		return -(int)GetLastError();
	}

	SECURITY_ATTRIBUTES WritePipeAttr = {
		.nLength		= sizeof(WritePipeAttr),
		.lpSecurityDescriptor	= NULL,
		.bInheritHandle		= (pipe_for_exec == PCS_CO_OUT_PIPE_FOR_EXEC),
	};

	WritePipeHandle = CreateFileA(
		PipeNameBuffer,
		GENERIC_WRITE,
		0,                         // No sharing
		&WritePipeAttr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | (pipe_for_exec == PCS_CO_OUT_PIPE_FOR_EXEC ? 0 : FILE_FLAG_OVERLAPPED),
		NULL                       // Template file
		);

	if (INVALID_HANDLE_VALUE == WritePipeHandle) {
		dwError = GetLastError();
		CloseHandle(ReadPipeHandle);
		SetLastError(dwError);
		return -(int)dwError;
	}

	*in_file = (pipe_for_exec == PCS_CO_IN_PIPE_FOR_EXEC) ? pcs_co_file_alloc_dummy(ReadPipeHandle) : pcs_co_file_alloc_regular(ReadPipeHandle, O_RDONLY);
	*out_file = (pipe_for_exec == PCS_CO_OUT_PIPE_FOR_EXEC) ? pcs_co_file_alloc_dummy(WritePipeHandle) : pcs_co_file_alloc_regular(WritePipeHandle, O_WRONLY);
	return 0;
}

int pcs_co_open_dev_null(int flags, struct pcs_co_file ** file)
{
	/* convert flags and mode to CreateFile parameters */
	DWORD access;
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

	SECURITY_ATTRIBUTES attr = {
		.nLength		= sizeof(attr),
		.lpSecurityDescriptor	= NULL,
		.bInheritHandle		= TRUE,
	};

	HANDLE handle = CreateFileA("NUL", access, 0, &attr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle == INVALID_HANDLE_VALUE)
		return -(int)GetLastError();

	*file = pcs_co_file_alloc_dummy(handle);
	return 0;
}

/* -------------------------------------------------------------------------------------------------- */

struct _co_iocp
{
	struct pcs_iocp         iocp;
	struct pcs_co_event	op_ev;	/* signaled when I/O has completed */
	struct pcs_co_event	*co_ev;	/* signaled when I/O has completed or canceled */
};

/* -------------------------------------------------------------------------------------------------- */

static int _co_iocp_wsa_wait(HANDLE handle, struct _co_iocp *co_iocp)
{
	pcs_co_event_wait(co_iocp->co_ev);
	if (pcs_co_event_is_signaled(&co_iocp->op_ev))
		return pcs_iocp_result(&co_iocp->iocp);

	pcs_iocp_cancel(handle, &co_iocp->iocp);
	pcs_co_event_wait(&co_iocp->op_ev);
	int rc = pcs_co_ctx_is_canceled();
	BUG_ON(!rc);
	return rc;
}

static void _co_iocp_wsa_done(struct pcs_iocp *iocp)
{
	struct _co_iocp *co_iocp = container_of(iocp, struct _co_iocp, iocp);

	/* Order is important! */
	pcs_co_event_signal(&co_iocp->op_ev);
	pcs_co_event_signal(co_iocp->co_ev);
}

static int pcs_co_wsa_recv_impl(struct pcs_co_file *file, int iovcnt, WSABUF *iov, u32 flags)
{
	if (flags & CO_IO_NOWAIT) {
		DWORD wsa_flags = 0, rcvd;
		if (!WSARecv((SOCKET)file->fd, iov, iovcnt, &rcvd, &wsa_flags, NULL, NULL))
			return rcvd;
		int err = -(int)WSAGetLastError();
		return err == -WSAEWOULDBLOCK ? 0 : err;
	}

	struct pcs_coroutine *co = pcs_current_co;
	int total = 0;

	for (;;) {
		int rc;
		if ((rc = pcs_cancelable_prepare_wait(&co->io_wait, co->ctx)))
			return rc;

		struct _co_iocp co_iocp = {.iocp = {.done = _co_iocp_wsa_done}, .co_ev = &co->io_wait.ev};
		DWORD wsa_flags = 0, rcvd;
		if (WSARecv((SOCKET)file->fd, iov, iovcnt, &rcvd, &wsa_flags, &co_iocp.iocp.overlapped, NULL)) {
			rc = -(int)WSAGetLastError();
			if (rc == -WSA_IO_PENDING)
				rc = _co_iocp_wsa_wait(file->fd, &co_iocp);
		} else if (file->skip_sync_notify) {
			rc = rcvd;
		} else {
			pcs_co_event_wait(&co_iocp.op_ev);
			rc = pcs_iocp_result(&co_iocp.iocp);
		}

		if (rc <= 0)
			return total ? total : rc;

		total += rc;
		if (flags & CO_IO_PARTIAL)
			break;

		while (iovcnt && rc >= iov->len) {
			rc -= iov->len;
			iov++;
			iovcnt--;
		}
		if (iovcnt == 0)
			break;

		iov->len -= rc;
		iov->buf += rc;
	}
	return total;
}

static int pcs_co_wsa_send_impl(struct pcs_co_file *file, int iovcnt, WSABUF *iov, u32 flags)
{
	if (flags & CO_IO_NOWAIT) {
		DWORD sent;
		if (!WSASend((SOCKET)file->fd, iov, iovcnt, &sent, 0, NULL, NULL))
			return sent;
		int err = -(int)WSAGetLastError();
		return err == -WSAEWOULDBLOCK ? 0 : err;
	}

	struct pcs_coroutine *co = pcs_current_co;
	int total = 0;

	for (;;) {
		int rc;
		if ((rc = pcs_cancelable_prepare_wait(&co->io_wait, co->ctx)))
			return rc;

		struct _co_iocp co_iocp = {.iocp = {.done = _co_iocp_wsa_done}, .co_ev = &co->io_wait.ev};
		DWORD sent;
		if (WSASend((SOCKET)file->fd, iov, iovcnt, &sent, 0, &co_iocp.iocp.overlapped, NULL)) {
			rc = -(int)WSAGetLastError();
			if (rc == -WSA_IO_PENDING)
				rc = _co_iocp_wsa_wait(file->fd, &co_iocp);
		} else if (file->skip_sync_notify) {
			rc = sent;
		} else {
			pcs_co_event_wait(&co_iocp.op_ev);
			rc = pcs_iocp_result(&co_iocp.iocp);
		}

		if (rc < 0)
			return rc;

		BUG_ON(!rc);
		total += rc;
		if (flags & CO_IO_PARTIAL)
			break;

		while (iovcnt && rc >= iov->len) {
			rc -= iov->len;
			iov++;
			iovcnt--;
		}
		if (iovcnt == 0)
			break;

		iov->len -= rc;
		iov->buf += rc;
	}
	return total;
}

static int pcs_co_wsa_recv(struct pcs_co_file *file, char *buf, int size, u64 offset, u32 flags)
{
	WSABUF wsa_buf = {.buf = buf, .len = size};
	return pcs_co_wsa_recv_impl(file, 1, &wsa_buf, flags);
}

static int pcs_co_wsa_send(struct pcs_co_file *file, const char *buf, int size, u64 offset, u32 flags)
{
	WSABUF wsa_buf = {.buf = (char *)buf, .len = size};
	return pcs_co_wsa_send_impl(file, 1, &wsa_buf, flags);
}

#define WSA_STACK_BUF_SIZE	16

static int pcs_co_wsa_recv_v(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u64 offset, u32 flags)
{
	WSABUF stack_buf[WSA_STACK_BUF_SIZE];
	WSABUF *buf = stack_buf;
	if (iovcnt > WSA_STACK_BUF_SIZE)
		buf = pcs_xmalloc(iovcnt * sizeof(*buf));

	int i;
	for (i = 0; i < iovcnt; i++) {
		buf[i].buf = iov[i].iov_base;
		buf[i].len = (ULONG)iov[i].iov_len;
	}
	int rc = pcs_co_wsa_recv_impl(file, iovcnt, buf, flags);

	if (buf != stack_buf)
		pcs_free(buf);
	return rc;
}

static int pcs_co_wsa_send_v(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u64 offset, u32 flags)
{
	WSABUF stack_buf[WSA_STACK_BUF_SIZE];
	WSABUF *buf = stack_buf;
	if (iovcnt > WSA_STACK_BUF_SIZE)
		buf = pcs_xmalloc(iovcnt * sizeof(*buf));

	int i;
	for (i = 0; i < iovcnt; i++) {
		buf[i].buf = iov[i].iov_base;
		buf[i].len = (ULONG)iov[i].iov_len;
	}
	int rc = pcs_co_wsa_send_impl(file, iovcnt, buf, flags);

	if (buf != stack_buf)
		pcs_free(buf);
	return rc;
}

/* -------------------------------------------------------------------------------------------------- */

static void _co_iocp_file_done(struct pcs_iocp *iocp)
{
	struct _co_iocp *co_iocp = container_of(iocp, struct _co_iocp, iocp);

	pcs_co_event_signal(&co_iocp->op_ev);
}

static int pcs_co_iocp_read_file(struct pcs_co_file *file, void *buf, int size, u64 offset, u32 flags)
{
	struct _co_iocp co_iocp = {.iocp = {.overlapped = {.Offset = (DWORD)offset, .OffsetHigh = (DWORD)(offset >> 32)}, .done = _co_iocp_file_done}};
	int rc;
	if (!ReadFile(file->fd, buf, size, NULL, &co_iocp.iocp.overlapped)) {
		rc = -(int)GetLastError();
		if (rc == -ERROR_IO_PENDING) {
			pcs_co_event_wait(&co_iocp.op_ev);
			rc = pcs_iocp_result(&co_iocp.iocp);
		}
	} else {
		if (!file->skip_sync_notify)
			pcs_co_event_wait(&co_iocp.op_ev);
		rc = pcs_iocp_result(&co_iocp.iocp);
	}

	if (rc == -ERROR_HANDLE_EOF || rc == -ERROR_BROKEN_PIPE)
		rc = 0;
	return rc;
}

static int pcs_co_iocp_write_file(struct pcs_co_file *file, const void * buf, int size, u64 offset, u32 flags)
{
	struct _co_iocp co_iocp = {.iocp = {.overlapped = {.Offset = (DWORD)offset, .OffsetHigh = (DWORD)(offset >> 32)}, .done = _co_iocp_file_done}};
	int rc;
	if (!WriteFile(file->fd, buf, size, NULL, &co_iocp.iocp.overlapped)) {
		rc = -(int)GetLastError();
		if (rc == -ERROR_IO_PENDING) {
			pcs_co_event_wait(&co_iocp.op_ev);
			rc = pcs_iocp_result(&co_iocp.iocp);
		}
	} else {
		if (!file->skip_sync_notify)
			pcs_co_event_wait(&co_iocp.op_ev);
		rc = pcs_iocp_result(&co_iocp.iocp);
	}

	return rc;
}

/* -------------------------------------------------------------------------------------------------- */

static int pcs_preadv_supported(int flag)
{
	return flag & O_DIRECT;
}

struct _co_io_req_rwv {
	struct _co_iocp		iocp;
	struct pcs_process	*proc;
	HANDLE			handle;
	int			size;
	int			error;
	FILE_SEGMENT_ELEMENT	seg[0];
};

static int _co_io_req_rwv_alloc(const struct iovec *iov, int iovcnt, struct _co_io_req_rwv **reqp)
{
	static unsigned sys_page_size;
	if (!sys_page_size)
		sys_page_size = pcs_sys_page_size();

	size_t total = 0;
	int i;
	for (i = 0; i < iovcnt; i++)
		total += iov[i].iov_len;
	if (!total || total > INT_MAX)
		return -ERROR_INVALID_PARAMETER;

	struct _co_io_req_rwv *req = pcs_xmalloc(sizeof(*req) + (total / sys_page_size + 1) * sizeof(FILE_SEGMENT_ELEMENT));
	memset(req, 0, sizeof(*req));

	FILE_SEGMENT_ELEMENT *cur = req->seg;
	for (i = 0; i < iovcnt; i++) {
		u8 *buf = iov[i].iov_base;
		size_t len = iov[i].iov_len;
		while (len >= sys_page_size) {
			cur->Buffer = buf;
			cur++;
			buf += sys_page_size;
			len -= sys_page_size;
		}
		if (len) {
			pcs_free(req);
			return -ERROR_INVALID_PARAMETER;
		}
	}
	cur->Buffer = NULL;

	req->size = (int)total;
	req->iocp.iocp.done = _co_iocp_file_done;
	req->proc = pcs_current_proc;

	*reqp = req;
	return 0;
}

static int _co_sync_io_readv(void *arg)
{
	struct _co_io_req_rwv *req = arg;

	if (!ReadFileScatter(req->handle, req->seg, req->size, NULL, &req->iocp.iocp.overlapped)) {
		int err = -(int)GetLastError();
		if (err != -ERROR_IO_PENDING) {
			req->error = err;
			pcs_iocp_send(req->proc, &req->iocp.iocp);
		}
	}
	return 0;
}

static int pcs_co_iocp_readv_file(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u64 offset, u32 flags)
{
	struct _co_io_req_rwv* req;
	int rc;

	if ((rc = _co_io_req_rwv_alloc(iov, iovcnt, &req)))
		return rc;

	req->iocp.iocp.overlapped.Offset = (DWORD)offset;
	req->iocp.iocp.overlapped.OffsetHigh = (DWORD)(offset >> 32);
	req->handle = file->fd;

	struct pcs_file_job *job = pcs_file_job_alloc(_co_sync_io_readv, req);
	pcs_file_job_submit(req->proc->co_io, job);

	pcs_co_event_wait(&req->iocp.op_ev);
	rc = req->error ? req->error : pcs_iocp_result(&req->iocp.iocp);
	if (rc == -ERROR_HANDLE_EOF || rc == -ERROR_BROKEN_PIPE)
		rc = 0;

	pcs_free(req);
	return rc;
}

static int _co_sync_io_writev(void *arg)
{
	struct _co_io_req_rwv *req = arg;

	if (!WriteFileGather(req->handle, req->seg, req->size, NULL, &req->iocp.iocp.overlapped)) {
		int err = -(int)GetLastError();
		if (err != -ERROR_IO_PENDING) {
			req->error = err;
			pcs_iocp_send(req->proc, &req->iocp.iocp);
		}
	}
	return 0;
}

static int pcs_co_iocp_writev_file(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u64 offset, u32 flags)
{
	struct _co_io_req_rwv* req;
	int rc;

	if ((rc = _co_io_req_rwv_alloc(iov, iovcnt, &req)))
		return rc;

	req->iocp.iocp.overlapped.Offset = (DWORD)offset;
	req->iocp.iocp.overlapped.OffsetHigh = (DWORD)(offset >> 32);
	req->handle = file->fd;

	struct pcs_file_job *job = pcs_file_job_alloc(_co_sync_io_writev, req);
	pcs_file_job_submit(req->proc->co_io, job);

	pcs_co_event_wait(&req->iocp.op_ev);
	rc = req->error ? req->error : pcs_iocp_result(&req->iocp.iocp);

	pcs_free(req);
	return rc;
}

/* -------------------------------------------------------------------------------------------------- */

static u8 sock_can_skip_sync_notify(int sa_family)
{
	return sa_family == AF_INET ? can_skip_sync_notifications : 0;
}

static int pcs_co_connect_sa(struct sockaddr * sa, socklen_t sa_len, struct pcs_co_file ** file_out)
{
	struct sockaddr_in bind_sa;
	struct pcs_coroutine *co = pcs_current_co;
	pcs_sock_t fd;
	int err;

	while (1) {
		fd = socket(sa->sa_family, SOCK_STREAM, 0);
		if (!pcs_sock_invalid(fd))
			break;

		err = pcs_sock_errno();
		if (pcs_fd_gc_on_error(pcs_current_proc, err, 1) <= 0)
			return -err;
	}

	pcs_sock_keepalive(fd);
	pcs_sock_nodelay(fd);

	struct pcs_co_file *file = pcs_co_file_alloc_socket(fd);

	bind_sa.sin_family = AF_INET;
	bind_sa.sin_addr.s_addr = htonl(INADDR_ANY);
	bind_sa.sin_port = 0;

	if (bind(fd, (struct sockaddr*)&bind_sa, sizeof(bind_sa))) {
		err = -(int)WSAGetLastError();
		goto fail;
	}

	if ((err = pcs_cancelable_prepare_wait(&co->io_wait, co->ctx)))
		goto fail;

	struct _co_iocp co_iocp = {.iocp = {.done = _co_iocp_wsa_done}, .co_ev = &co->io_wait.ev};
	if (!pcs_connectex(fd, sa, sa_len, NULL, 0, NULL, &co_iocp.iocp.overlapped)) {
		err = -(int)WSAGetLastError();
		if (err == -WSA_IO_PENDING)
			err = _co_iocp_wsa_wait((HANDLE)fd, &co_iocp);
	} else {
		pcs_co_event_wait(&co_iocp.op_ev);
		err = pcs_iocp_result(&co_iocp.iocp);
	}

	if (err < 0)
		goto fail;

	if (setsockopt(fd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0)) {
		err = -(int)WSAGetLastError();
		goto fail;
	}

	*file_out = file;
	disable_notifications(*file_out, sock_can_skip_sync_notify(sa->sa_family));

	return 0;

fail:
	pcs_co_file_close(file);
	return err;
}

static int pcs_co_accept_sa(struct pcs_co_file *listen, struct sockaddr * sa, socklen_t * sa_len,
		  struct pcs_co_file ** file_out)
{
	struct
	{
		struct sockaddr_storage sa;
		char _pad[16];
	} buf[2];
	struct pcs_coroutine *co = pcs_current_co;
	pcs_sock_t accepted_sock;
	int err;

	WSAPROTOCOL_INFO info;
	int len = sizeof(info);
	if (getsockopt(pcs_co_file_sock(listen), SOL_SOCKET, SO_PROTOCOL_INFO, (char*)&info, &len))
		return -pcs_sock_errno();

	while (1) {
		accepted_sock = socket(info.iAddressFamily, SOCK_STREAM, 0);
		if (!pcs_sock_invalid(accepted_sock))
			break;

		err = pcs_sock_errno();
		if (pcs_fd_gc_on_error(pcs_current_proc, err, PCS_GC_FD_ON_ACCEPT) <= 0)
			return -err;
	}

	if ((err = pcs_cancelable_prepare_wait(&co->io_wait, co->ctx)))
		goto fail;

	struct _co_iocp co_iocp = {.iocp = {.done = _co_iocp_wsa_done}, .co_ev = &co->io_wait.ev};
	if (!pcs_acceptex((SOCKET)listen->fd, accepted_sock, &buf[0], 0, sizeof(buf[0]), sizeof(buf[1]), NULL, &co_iocp.iocp.overlapped)) {
		err = -(int)WSAGetLastError();
		if (err == -WSA_IO_PENDING)
			err = _co_iocp_wsa_wait(listen->fd, &co_iocp);
	} else {
		pcs_co_event_wait(&co_iocp.op_ev);
		err = pcs_iocp_result(&co_iocp.iocp);
	}

	if (err < 0)
		goto fail;

	if (setsockopt(accepted_sock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&accepted_sock, sizeof(accepted_sock))) {
		err = -(int)WSAGetLastError();
		goto fail;
	}

	if (getsockname(accepted_sock, sa, sa_len)) {
		err = -(int)WSAGetLastError();
		goto fail;
	}

	pcs_sock_keepalive(accepted_sock);
	pcs_sock_nodelay(accepted_sock);

	*file_out = pcs_co_file_alloc_socket(accepted_sock);
	disable_notifications(*file_out, sock_can_skip_sync_notify(sa->sa_family));

	return 0;

fail:
	pcs_sock_close(accepted_sock);
	return err;
}

static int pcs_co_iocp_close_file(struct pcs_co_file *file)
{
	CloseHandle(file->fd);
	pcs_free(file);
	return 0;
}

static int pcs_co_wsa_close(struct pcs_co_file *file)
{
	closesocket((SOCKET)file->fd);
	pcs_free(file);
	return 0;
}

struct pcs_co_file *pcs_co_file_alloc_socket(pcs_sock_t sock)
{
	pcs_sock_nonblock(sock);
	return pcs_co_file_alloc((pcs_fd_t)sock, &pcs_co_sock_ops);
}

void pcs_co_file_pool_free(struct pcs_process *proc)
{
}

#endif /* __WINDOWS__ */

/* -------------------------------------------------------------------------------------------------- */

void pcs_co_file_init(struct pcs_co_file *file, struct pcs_co_file_ops *ops)
{
	file->ops = ops;
	file->fd = PCS_INVALID_FD;
}

static struct pcs_co_file *pcs_co_file_alloc_dummy(pcs_fd_t fd)
{
	struct pcs_co_file *file = pcs_xzmalloc(sizeof(*file));

	file->ops = &pcs_co_dummy_ops;
	file->fd = fd;

	return file;
}

static struct pcs_co_file *pcs_co_file_alloc(pcs_fd_t fd, const struct pcs_co_file_ops *ops)
{
	struct pcs_co_file *file = pcs_xzmalloc(sizeof(*file));

	file->ops = ops;
	file->fd = fd;

#ifdef __WINDOWS__
	pcs_iocp_attach(pcs_current_proc, fd, file);
#endif

	return file;
}

struct pcs_co_file *pcs_co_file_alloc_regular(pcs_fd_t fd, int flag)
{
	int preadv_supported = pcs_preadv_supported(flag);
	struct pcs_co_file *file = pcs_co_file_alloc(fd, preadv_supported ? &pcs_co_file_with_preadv_ops : &pcs_co_file_ops);

#ifdef __WINDOWS__
	/* Implementation of pcs_co_iocp_readv_file/pcs_co_iocp_writev_file requires that sync notifications are enabled */
	disable_notifications(file, !preadv_supported);
#endif
#ifdef __MAC__
	pcs_co_mutex_init(&file->wr_mutex);
	file->wr_offs = ~0ull;
#endif
	return file;
}

int pcs_co_file_close(struct pcs_co_file *file)
{
	if (!file)
		return 0;

	return file->ops->close(file);
}

// ------------------------------------------------------------------------------------------------

/* TODO: kill timeout_p argument also... everything to be done via context... */
int pcs_co_io_wait_cancelable(int *timeout_p)
{
	struct pcs_coroutine *co = pcs_current_co;
	int err;

	if ((err = pcs_cancelable_prepare_wait(&co->io_wait, co->ctx)))
		return err;

	if ((err = pcs_co_event_wait_timeout(&co->io_wait.ev, timeout_p)))
		return err;

	return pcs_context_is_canceled(co->ctx);
}

int pcs_co_io_wait_cancelable_wq(struct pcs_co_waitqueue *wq, int *timeout)
{
	pcs_co_waitqueue_add(wq);
	int res = pcs_co_io_wait_cancelable(timeout);
	pcs_co_waitqueue_remove();
	return res;
}

/* -------------------------------------------------------------------------------------------------- */

struct _co_io_req_open
{
	const char * pathname;
	int flag;
	int mode;
	pcs_fd_t * out_fd;
};

static int _co_sync_io_open(void * arg)
{
	struct _co_io_req_open * req = arg;
	return pcs_sync_open(req->pathname, req->flag, req->mode, req->out_fd);
}

int pcs_co_file_open(const char * pathname, int flag, int mode, struct pcs_co_file ** out_file)
{
	pcs_fd_t fd;
	struct _co_io_req_open req = {
		.pathname = pathname,
		.flag = flag,
		.mode = mode,
		.out_fd = &fd,
	};
	int rc = pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_open, &req);
	if (rc)
		return rc;

	*out_file = pcs_co_file_alloc_regular(fd, flag);
	return 0;
}

struct _co_io_req_openat
{
	pcs_fd_t dirfd;
	const char * pathname;
	int flag;
	int mode;
	pcs_fd_t * out_fd;
};

static int _co_sync_io_openat(void * arg)
{
	struct _co_io_req_openat * req = arg;
	return pcs_sync_openat(req->dirfd, req->pathname, req->flag, req->mode, req->out_fd);
}

int pcs_co_file_openat(struct pcs_co_file * dir, const char * pathname, int flag, int mode, struct pcs_co_file ** out_file)
{
	pcs_fd_t fd;
	struct _co_io_req_openat req = {
		.dirfd = pcs_co_file_fd(dir),
		.pathname = pathname,
		.flag = flag,
		.mode = mode,
		.out_fd = &fd,
	};
	int rc = pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_openat, &req);
	if (rc)
		return rc;

	*out_file = pcs_co_file_alloc_regular(fd, flag);
	return 0;
}

/* -------------------------------------------------------------------------------------------------- */

static int __pcs_co_file_readv(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u64 offset, u32 flags)
{
	if (file->ops->readv != NULL)
		return file->ops->readv(file, iovcnt, iov, offset, flags);

	u64 nr_bytes_total = 0;
	const struct iovec *i;
	for (i = &iov[0]; i != &iov[iovcnt]; ++i) {
		int r = file->ops->read(file, i->iov_base, (int)i->iov_len, offset, flags);
		if (r < 0)
			return r;

		nr_bytes_total += r;
		offset += r;

		BUG_ON(nr_bytes_total >= (u32)INT32_MAX);

		if (r < (int)i->iov_len)
			break;

		if (flags & CO_IO_PARTIAL)
			flags |= CO_IO_NOWAIT; // the following read need not make any progress
	}
	return (int)nr_bytes_total;
}

static int __pcs_co_file_writev(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u64 offset, u32 flags)
{
	if (file->ops->writev != NULL)
		return file->ops->writev(file, iovcnt, iov, offset, flags);

	u64 nr_bytes_total = 0;
	const struct iovec *i;
	for (i = &iov[0]; i != &iov[iovcnt]; ++i) {
		int r = file->ops->write(file, i->iov_base, (int)i->iov_len, offset, flags);
		if (r < 0)
			return r;

		nr_bytes_total += r;
		offset += r;

		BUG_ON(nr_bytes_total >= (u32)INT32_MAX);

		if (r < (int)i->iov_len)
			break;

		if (flags & CO_IO_PARTIAL)
			flags |= CO_IO_NOWAIT; // the following write need not make any progress
	}
	return (int)nr_bytes_total;
}

int pcs_co_file_read(struct pcs_co_file *file, void * buf, int size, u64 offset)
{
	return file->ops->read(file, buf, size, offset, 0);
}

int pcs_co_file_write(struct pcs_co_file *file, const void * buf, int size, u64 offset)
{
	return file->ops->write(file, buf, size, offset, 0);
}

int pcs_co_file_readv(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u64 offset)
{
	return __pcs_co_file_readv(file, iovcnt, iov, offset, 0);
}

int pcs_co_file_writev(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u64 offset)
{
	return __pcs_co_file_writev(file, iovcnt, iov, offset, 0);
}

int pcs_co_file_read_ex(struct pcs_co_file *file, void * buf, int size, u32 flags)
{
	return file->ops->read(file, buf, size, 0, flags);
}

int pcs_co_file_write_ex(struct pcs_co_file *file, const void * buf, int size, u32 flags)
{
	return file->ops->write(file, buf, size, 0, flags);
}

int pcs_co_file_readv_ex(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u32 flags)
{
	return __pcs_co_file_readv(file, iovcnt, iov, 0, flags);
}

int pcs_co_file_writev_ex(struct pcs_co_file *file, int iovcnt, struct iovec *iov, u32 flags)
{
	return __pcs_co_file_writev(file, iovcnt, iov, 0, flags);
}

int pcs_co_file_sync(struct pcs_co_file *file, u32 flags)
{
	if (!file->ops->sync)
		return 0;

	return file->ops->sync(file, flags);
}

/* -------------------------------------------------------------------------------------------------- */

struct _co_io_req_mkdir
{
	const char * pathname;
	int mode;
};

static int _co_sync_io_mkdir(void * arg)
{
	struct _co_io_req_mkdir * req = arg;
	return pcs_sync_mkdir(req->pathname, req->mode);
}

int pcs_co_mkdir(const char * pathname, int mode)
{
	struct _co_io_req_mkdir req = {
		.pathname = pathname,
		.mode = mode,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_mkdir, &req);
}

struct _co_io_req_mkdirat
{
	pcs_fd_t dirfd;
	const char * pathname;
	int mode;
};

static int _co_sync_io_mkdirat(void * arg)
{
	struct _co_io_req_mkdirat * req = arg;
	return pcs_sync_mkdirat(req->dirfd, req->pathname, req->mode);
}

int pcs_co_mkdirat(pcs_fd_t dirfd, const char * pathname, int mode)
{
	BUG_ON(dirfd < 0);
	struct _co_io_req_mkdirat req = {
		.dirfd = dirfd,
		.pathname = pathname,
		.mode = mode,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_mkdirat, &req);
}

/* -------------------------------------------------------------------------------------------------- */

static int _co_sync_io_rmdir(void * pathname)
{
	return pcs_sync_rmdir((const char *)pathname);
}

int pcs_co_rmdir(const char * pathname)
{
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_rmdir, (void *)pathname);
}

struct _co_io_req_rmdirat
{
	pcs_fd_t dirfd;
	const char * pathname;
};

static int _co_sync_io_rmdirat(void * arg)
{
	struct _co_io_req_rmdirat * req = arg;
	return pcs_sync_rmdirat(req->dirfd, req->pathname);
}

int pcs_co_rmdirat(pcs_fd_t dirfd, const char * pathname)
{
	BUG_ON(dirfd < 0);
	struct _co_io_req_rmdirat req = {
		.dirfd = dirfd,
		.pathname = pathname,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_rmdirat, &req);
}

/* -------------------------------------------------------------------------------------------------- */

static int _co_sync_io_unlink(void * pathname)
{
	return pcs_sync_unlink((const char *)pathname);
}

int pcs_co_file_unlink(const char * pathname)
{
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_unlink, (void *)pathname);
}

struct _co_io_req_unlinkat
{
	pcs_fd_t dirfd;
	const char * pathname;
	int flags;
};

static int _co_sync_io_unlinkat(void * arg)
{
	struct _co_io_req_unlinkat * req = arg;
	return pcs_sync_unlinkat(req->dirfd, req->pathname, req->flags);
}

int pcs_co_file_unlinkat(pcs_fd_t dirfd, const char * pathname, int flags)
{
	BUG_ON(dirfd < 0);
	struct _co_io_req_unlinkat req = {
		.dirfd = dirfd,
		.pathname = pathname,
		.flags = flags,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_unlinkat, &req);
}

/* -------------------------------------------------------------------------------------------------- */

struct _co_io_req_rename
{
	const char * oldpath;
	const char * newpath;
};

static int _co_sync_io_rename(void * arg)
{
	struct _co_io_req_rename * req = arg;
	return pcs_sync_rename(req->oldpath, req->newpath);
}

int pcs_co_file_rename(const char * oldpath, const char * newpath)
{
	struct _co_io_req_rename req = {
		.oldpath = oldpath,
		.newpath = newpath,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_rename, &req);
}

/* -------------------------------------------------------------------------------------------------- */

struct _co_io_req_renameat
{
	pcs_fd_t olddirfd;
	const char * oldpath;
	pcs_fd_t newdirfd;
	const char * newpath;
};

static int _co_sync_io_renameat(void * arg)
{
	struct _co_io_req_renameat * req = arg;
	return pcs_sync_renameat(req->olddirfd, req->oldpath, req->newdirfd, req->newpath);
}

int pcs_co_file_renameat(pcs_fd_t olddirfd, const char * oldpath, pcs_fd_t newdirfd, const char * newpath)
{
	BUG_ON(olddirfd < 0);
	BUG_ON(newdirfd < 0);
	struct _co_io_req_renameat req = {
		.olddirfd = olddirfd,
		.oldpath = oldpath,
		.newdirfd = newdirfd,
		.newpath = newpath,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_renameat, &req);
}

/* -------------------------------------------------------------------------------------------------- */

struct _co_io_req_getfsize
{
	pcs_fd_t fd;
	u64 * size;
};

static int _co_sync_io_getfsize(void * arg)
{
	struct _co_io_req_getfsize * req = arg;
	return pcs_sync_getfsize(req->fd, req->size);
}

int pcs_co_file_getfsize(pcs_fd_t fd, u64 * size)
{
	struct _co_io_req_getfsize req = {
		.fd = fd,
		.size = size,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_getfsize, &req);
}

/* -------------------------------------------------------------------------------------------------- */

struct _co_io_req_fallocate
{
	pcs_fd_t fd;
	u64 size;
	u64 offset;
};

static int _co_sync_io_punch_hole(void * arg)
{
	struct _co_io_req_fallocate * req = arg;
	return pcs_sync_punch_hole(req->fd, req->offset, req->size);
}

int pcs_co_file_punch_hole(pcs_fd_t fd, u64 size, u64 offset)
{
	struct _co_io_req_fallocate req = {
		.fd = fd,
		.size = size,
		.offset = offset,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_punch_hole, &req);
}

/* -------------------------------------------------------------------------------------------------- */

static int _co_sync_io_make_sparse(void * fd)
{
	return pcs_sync_make_sparse(*(pcs_fd_t *)fd);
}

int pcs_co_file_make_sparse(pcs_fd_t fd)
{
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_make_sparse, &fd);
}

/* -------------------------------------------------------------------------------------------------- */

static int _co_sync_io_fallocate(void * arg)
{
	struct _co_io_req_fallocate * req = arg;
	return pcs_sync_fallocate(req->fd, req->offset, req->size);
}

int pcs_co_file_fallocate(pcs_fd_t fd, u64 size, u64 offset)
{
	struct _co_io_req_fallocate req = {
		.fd = fd,
		.size = size,
		.offset = offset,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_fallocate, &req);
}

/* -------------------------------------------------------------------------------------------------- */

struct _co_io_req_fsync
{
	pcs_fd_t fd;
	u32 flags;
};

static int _co_sync_io_fsync(void * arg)
{
	struct _co_io_req_fsync * req = arg;
	if (req->flags & CO_IO_DATASYNC)
		return pcs_sync_fdatasync(req->fd);
	else
		return pcs_sync_fsync(req->fd);
}

static int pcs_co_sync_fsync(struct pcs_co_file *file, u32 flags)
{
	struct _co_io_req_fsync req = {
		.fd = file->fd,
		.flags = flags,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_fsync, &req);
}

/* -------------------------------------------------------------------------------------------------- */

struct _co_io_req_ftruncate
{
	pcs_fd_t fd;
	u64 len;
};

static int _co_sync_io_ftruncate(void * arg)
{
	struct _co_io_req_ftruncate * req = arg;
	return pcs_sync_ftruncate(req->fd, req->len);
}

int pcs_co_file_ftruncate(pcs_fd_t fd, u64 len)
{
	struct _co_io_req_ftruncate req = {
		.fd = fd,
		.len = len,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_ftruncate, &req);
}

/* -------------------------------------------------------------------------------------------------- */

struct _co_io_req_stat
{
	const char * path;
	int flags;
	struct pcs_stat *res;
};

static int _co_sync_io_stat(void * arg)
{
	struct _co_io_req_stat * req = arg;
	return pcs_sync_stat(req->path, req->flags, req->res);
}

int pcs_co_file_stat(const char * path, int flags, struct pcs_stat * res)
{
	struct _co_io_req_stat req = {
		.path = path,
		.flags = flags,
		.res = res,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_stat, &req);
}

/* -------------------------------------------------------------------------------------------------- */

struct _co_io_req_fstat
{
	pcs_fd_t fd;
	struct pcs_stat *res;
};

static int _co_sync_io_fstat(void * arg)
{
	struct _co_io_req_fstat * req = arg;
	return pcs_sync_fstat(req->fd, req->res);
}

int pcs_co_file_fstat(pcs_fd_t fd, struct pcs_stat * res)
{
	struct _co_io_req_fstat req = {
		.fd = fd,
		.res = res,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_fstat, &req);
}

struct _co_io_req_fstatat
{
	pcs_fd_t dirfd;
	const char *filename;
	struct pcs_stat *res;
};

static int _co_sync_io_fstatat(void * arg)
{
	struct _co_io_req_fstatat * req = arg;
	return pcs_sync_fstatat(req->dirfd, req->filename, req->res);
}

int pcs_co_file_fstatat(pcs_fd_t dirfd, const char *filename, struct pcs_stat *res)
{
	BUG_ON(dirfd < 0);
	struct _co_io_req_fstatat req = {
		.dirfd = dirfd,
		.filename = filename,
		.res = res,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_fstatat, &req);
}

/* -------------------------------------------------------------------------------------------------- */

struct _co_io_req_statvfs
{
	const char * path;
	struct pcs_statvfs * res;
};

static int _co_sync_io_statvfs(void * arg)
{
	struct _co_io_req_statvfs * req = arg;
	return pcs_sync_statvfs(req->path, req->res);
}

int pcs_co_statvfs(const char * path, struct pcs_statvfs * res)
{
	struct _co_io_req_statvfs req = {
		.path = path,
		.res = res,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_statvfs, &req);
}

/* -------------------------------------------------------------------------------------------------- */

struct _co_io_req_ioctl
{
	pcs_fd_t fd;
	unsigned long int cmd;
	void *data;
};

static int _co_sync_io_ioctl(void * arg)
{
	struct _co_io_req_ioctl * req = arg;
	return pcs_sync_ioctl(req->fd, req->cmd, req->data);
}

int pcs_co_file_ioctl(pcs_fd_t fd, unsigned long int cmd, void *data)
{
	struct _co_io_req_ioctl req = {
		.fd = fd,
		.cmd = cmd,
		.data = data
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_ioctl, &req);
}

/* -------------------------------------------------------------------------------------------------- */

struct _co_io_req_lock
{
	pcs_fd_t fd;
	int cmd;
	short int type;
	u64 offs;
	u64 len;
};

static int _co_sync_io_lock(void * arg)
{
	struct _co_io_req_lock * req = arg;
	return pcs_sync_lock(req->fd, req->cmd, req->type, req->offs, req->len);
}

int pcs_co_file_lock(pcs_fd_t fd, int cmd, short int type, u64 offs, u64 len)
{
	struct _co_io_req_lock req = {
		.fd = fd,
		.cmd = cmd,
		.type = type,
		.offs = offs,
		.len = len,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_lock, &req);
}

/* -------------------------------------------------------------------------------------------------- */

static int _co_sync_io_close(void * arg)
{
	return pcs_sync_close((pcs_fd_t)(intptr_t)arg);
}

int pcs_co_file_close_fd(pcs_fd_t fd)
{
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_close, (void*)(intptr_t)fd);
}

/* -------------------------------------------------------------------------------------------------- */

static int pcs_co_listen_sa(struct sockaddr * sa, unsigned int sa_len, int flags, struct pcs_co_file ** file_out)
{
	int val, err;
	pcs_sock_t fd;

	fd = pcs_new_socket(sa->sa_family, SOCK_STREAM);
	if (pcs_sock_invalid(fd))
		return -pcs_sock_errno();;

	val = 1;
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&val, sizeof(val));

	if (bind(fd, sa, sa_len)) {
#ifdef __linux__
#ifndef IP_FREEBIND     /* just in case old glibc is used */
#define IP_FREEBIND     15
#endif
		if ((errno != EADDRNOTAVAIL) || ((flags & PCS_CO_FREE_BIND) == 0))
			goto out_err;
		pcs_log(LOG_WARN, "bind() failed: %s; retrying with IP_FREEBIND",
				strerror(errno));
		(void)setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &val, sizeof(val));
		if (bind(fd, sa, sa_len))
#endif /* __linux__ */
			goto out_err;
	}

	if (listen(fd, 128))
		goto out_err;

	*file_out = pcs_co_file_alloc_socket(fd);
	return 0;

out_err:
	err = pcs_sock_errno();
	pcs_sock_close(fd);
	return -err;
}

int pcs_co_listen(PCS_NET_ADDR_T * na, int flags, struct pcs_co_file ** listen_out)
{
	struct sockaddr *sa = NULL;
	int sa_len = 0;
	int r;

	pcs_netaddr2sockaddr(na, &sa, &sa_len);
	if (sa == NULL)
		return -EAFNOSUPPORT;

	r = pcs_co_listen_sa(sa, sa_len, flags, listen_out);
	pcs_free(sa);
	return r;
}

int pcs_co_accept(struct pcs_co_file *listen, PCS_NET_ADDR_T * na, struct pcs_co_file ** file_out)
{
	struct sockaddr_storage sa;
	socklen_t sa_len = sizeof(sa);
	int r;

	if ((r = pcs_co_accept_sa(listen, (struct sockaddr *)&sa, &sa_len, file_out)))
		return r;

	if ((r = pcs_sockaddr2netaddr(na, (struct sockaddr *)&sa))) {
		pcs_co_file_close(*file_out);
		return r;
	}

	return 0;
}

int pcs_co_connect(PCS_NET_ADDR_T * na, struct pcs_co_file ** file_out)
{
	struct sockaddr *sa = NULL;
	int sa_len = 0;
	int r;

	pcs_netaddr2sockaddr(na, &sa, &sa_len);
	if (sa == NULL)
		return -EAFNOSUPPORT;

	r = pcs_co_connect_sa(sa, sa_len, file_out);
	pcs_free(sa);
	return r;
}

/* -------------------------------------------------------------------------------------------------- */

#ifndef __WINDOWS__
/* generic syncronous I/O redirected to co_io thread pool */
static const struct pcs_co_file_ops pcs_co_file_ops = {
	.read			= pcs_co_sync_read,
	.write			= pcs_co_sync_write,
	.readv			= NULL,
	.writev			= NULL,
	.sync			= pcs_co_sync_fsync,
	.close			= pcs_co_sync_close
};

#ifdef __LINUX__
static const struct pcs_co_file_ops pcs_co_file_with_preadv_ops = {
	.read			= pcs_co_sync_read,
	.write			= pcs_co_sync_write,
	.readv			= pcs_co_sync_readv,
	.writev			= pcs_co_sync_writev,
	.sync			= pcs_co_sync_fsync,
	.close			= pcs_co_sync_close
};
#endif

#ifdef __MAC__
static const struct pcs_co_file_ops pcs_co_file_with_preadv_ops = {
	.read = pcs_co_sync_read,
	.write = pcs_co_sync_write,
	.readv = NULL,
	.writev = pcs_co_sync_writev,
	.sync = pcs_co_sync_fsync,
	.close = pcs_co_sync_close
};
#endif

static const struct pcs_co_file_ops pcs_co_sock_ops = {
	.read			= pcs_co_nb_read,
	.write			= pcs_co_nb_write,
	.readv			= pcs_co_nb_readv,
	.writev			= pcs_co_nb_writev,
	.sync			= NULL,
	.close			= pcs_co_nb_close
};

static const struct pcs_co_file_ops pcs_co_dummy_ops = {
	.read			= NULL,
	.write			= NULL,
	.readv			= NULL,
	.writev			= NULL,
	.sync			= NULL,
	.close			= pcs_dummy_close
};

#else /* __WINDOWS__ */

static const struct pcs_co_file_ops pcs_co_file_ops = {
	.read			= pcs_co_iocp_read_file,
	.write			= pcs_co_iocp_write_file,
	.readv			= NULL,
	.writev			= NULL,
	.sync			= pcs_co_sync_fsync,
	.close			= pcs_co_iocp_close_file
};

static const struct pcs_co_file_ops pcs_co_file_with_preadv_ops = {
	.read			= pcs_co_iocp_read_file,
	.write			= pcs_co_iocp_write_file,
	.readv			= pcs_co_iocp_readv_file,
	.writev			= pcs_co_iocp_writev_file,
	.sync			= pcs_co_sync_fsync,
	.close			= pcs_co_iocp_close_file
};

static const struct pcs_co_file_ops pcs_co_sock_ops = {
	.read			= pcs_co_wsa_recv,
	.write			= pcs_co_wsa_send,
	.readv			= pcs_co_wsa_recv_v,
	.writev			= pcs_co_wsa_send_v,
	.sync			= NULL,
	.close			= pcs_co_wsa_close
};

static const struct pcs_co_file_ops pcs_co_dummy_ops = {
	.read			= NULL,
	.write			= NULL,
	.readv			= NULL,
	.writev			= NULL,
	.sync			= NULL,
	.close			= pcs_co_iocp_close_file
};

#endif /* __WINDOWS__ */
