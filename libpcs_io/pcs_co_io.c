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
#include "pcs_winapi.h"
#endif

static struct pcs_co_file_ops pcs_co_file_ops;
static struct pcs_co_file_ops pcs_co_sock_ops;
static struct pcs_co_file *pcs_co_file_alloc(pcs_fd_t fd, struct pcs_co_file_ops *ops);

/* -------------------------------------------------------------------------------------------------- */

#ifndef __WINDOWS__

int pcs_co_file_pipe(struct pcs_co_file ** in_file, struct pcs_co_file ** out_file)
{
	int pfd[2];

	if (pipe(pfd))
		return -errno;

	*in_file = pcs_co_file_alloc_socket(pfd[0]);
	*out_file = pcs_co_file_alloc_socket(pfd[1]);

	return 0;
}

/* -------------------------------------------------------------------------------------------------- */

#ifdef __LINUX__

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

int pcs_preadv_supported(void)
{
	int ret = syscall(SYS_preadv, -1, NULL, 0, (off_t)0);
	return !(ret == -1 && errno == ENOSYS);
}

struct _co_iov_req_rw
{
	struct pcs_file_job fjob;

	void (*cb)(void *arg, int res);
	void *arg;

	pcs_fd_t fd;
	u64 offset;

	int iovcnt;
	const struct iovec *iov;
};

static void _co_file_job_donev(void *arg)
{
	struct _co_iov_req_rw *req = (struct _co_iov_req_rw *)arg;

	req->cb(req->arg, req->fjob.retval);

	pcs_free(req);
}

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

void pcs_co_file_readv_async(struct pcs_co_file *file, const struct iovec *iov, int iovcnt, u64 offset, void (*cb)(void *arg, int res), void *arg)
{
	struct _co_iov_req_rw *req = pcs_xmalloc(sizeof(*req));

	req->fd = pcs_co_file_fd(file);
	req->offset = offset;
	req->cb = cb;
	req->arg = arg;
	req->iov = iov;
	req->iovcnt = iovcnt;

	struct pcs_file_job *fjob = &req->fjob;

	pcs_file_job_init(fjob, _co_file_job_readv, req);
	pcs_job_init(pcs_current_proc, &fjob->done, _co_file_job_donev, req);

	pcs_file_job_submit(pcs_current_proc->co_io, fjob);
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

void pcs_co_file_writev_async(struct pcs_co_file *file, const struct iovec *iov, int iovcnt, u64 offset, void (*cb)(void *arg, int res), void *arg)
{
	struct _co_iov_req_rw *req = pcs_xmalloc(sizeof(*req));

	req->fd = pcs_co_file_fd(file);
	req->offset = offset;
	req->cb = cb;
	req->arg = arg;
	req->iov = iov;
	req->iovcnt = iovcnt;

	struct pcs_file_job *fjob = &req->fjob;

	pcs_file_job_init(fjob, _co_file_job_writev, req);
	pcs_job_init(pcs_current_proc, &fjob->done, _co_file_job_donev, req);

	pcs_file_job_submit_hash(pcs_current_proc->co_io, fjob, (unsigned int)req->fd + (unsigned int)(offset / (4*1024*1024)));
}

#else /* __LINUX__ */

int pcs_preadv_supported(void)
{
	return 0;
}

void pcs_co_file_readv_async(struct pcs_co_file *file, const struct iovec *iov, int iovcnt, u64 offset, void (*cb)(void *arg, int res), void *arg)
{
	cb(arg, -ENOSYS);
}

void pcs_co_file_writev_async(struct pcs_co_file *file, const struct iovec *iov, int iovcnt, u64 offset, void (*cb)(void *arg, int res), void *arg)
{
	cb(arg, -ENOSYS);
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

static int pcs_co_nb_read(struct pcs_co_file *file, void * buf, int size, u64 offset, int * timeout_p, u32 flags)
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
		if ((err = pcs_co_event_wait_timeout(&file->reader.ev, timeout_p)))
			return err;
	}
	return total;
}

static int pcs_co_nb_write(struct pcs_co_file *file, const void * buf, int size, u64 offset, int * timeout_p, u32 flags)
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
		if ((err = pcs_co_event_wait_timeout(&file->writer.ev, timeout_p)))
			return err;
	}
	return total;
}

/* -------------------------------------------------------------------------------------------------- */

static int pcs_co_connect_sa(struct sockaddr * sa, unsigned int sa_len, struct pcs_co_file ** file_out, int * timeout_p)
{
	int fd, err;

	while ((fd = socket(sa->sa_family, SOCK_STREAM, 0)) < 0) {
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
		if ((err = pcs_co_event_wait_timeout(&file->writer.ev, timeout_p)))
			break;
	}

	pcs_co_file_close(file);
	return err;
}

static int pcs_co_accept_sa(struct pcs_co_file * listen, struct sockaddr * sa, unsigned int * sa_len,
			    struct pcs_co_file ** file_out, int * timeout_p)
{
	int fd;

	for (;;) {
		int err;
		if ((err = pcs_cancelable_prepare_wait(&listen->reader, pcs_current_co->ctx)))
			return err;

		fd = accept(pcs_co_file_sock(listen), sa, sa_len);
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
		if ((err = pcs_co_event_wait_timeout(&listen->reader.ev, timeout_p)))
			return err;
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

static int pcs_co_sync_read(struct pcs_co_file *file, void * buf, int size, u64 offset, int * timeout, u32 flags)
{
	struct _co_io_req_rw req = {
		.fd = pcs_co_file_fd(file),
		.buf = buf,
		.size = size,
		.offset = offset,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_read, &req);
}

static int _co_sync_io_write(void * arg)
{
	struct _co_io_req_rw * req = arg;
	return pcs_sync_nwrite(req->fd, req->offset, req->buf, req->size);
}

static int pcs_co_sync_write(struct pcs_co_file *file, const void * buf, int size, u64 offset, int * timeout, u32 flags)
{
	struct _co_io_req_rw req = {
		.fd = pcs_co_file_fd(file),
		.buf = (void *)buf,
		.size = size,
		.offset = offset,
	};
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_write, &req);
}

/* -------------------------------------------------------------------------------------------------- */

static int pcs_co_sync_close(struct pcs_co_file *file)
{
	/* close() can block on NFS or vstorage... */
	int rc = pcs_co_file_close_fd(pcs_co_file_fd(file));
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

	ReadPipeHandle = CreateNamedPipeA(
		PipeNameBuffer,
		PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_WAIT,
		1,              // Number of pipes
		PipeBufferSize, // Out buffer size
		PipeBufferSize, // In buffer size
		PipeTimeout,    // Timeout in ms
		NULL            // Pipe attributes
		);

	if (!ReadPipeHandle) {
		return -(int)GetLastError();
	}

	WritePipeHandle = CreateFileA(
		PipeNameBuffer,
		GENERIC_WRITE,
		0,                         // No sharing
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL                       // Template file
		);

	if (INVALID_HANDLE_VALUE == WritePipeHandle) {
		dwError = GetLastError();
		CloseHandle(ReadPipeHandle);
		SetLastError(dwError);
		return -(int)dwError;
	}

	*in_file = pcs_co_file_alloc_regular(ReadPipeHandle);
	*out_file = pcs_co_file_alloc_regular(WritePipeHandle);
	disable_notifications(*in_file, 1);
	disable_notifications(*out_file, 1);

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

static int _co_iocp_wsa_wait(HANDLE handle, struct _co_iocp *co_iocp, int *timeout)
{
	int rc = pcs_co_event_wait_timeout(co_iocp->co_ev, timeout);
	if (pcs_co_event_is_signaled(&co_iocp->op_ev))
		return pcs_iocp_result(&co_iocp->iocp);

	pcs_iocp_cancel(handle, &co_iocp->iocp);
	pcs_co_event_wait(&co_iocp->op_ev);
	if (!rc) {
		rc = pcs_co_ctx_is_canceled();
		BUG_ON(!rc);
	}
	return rc;
}

static void _co_iocp_wsa_done(struct pcs_iocp *iocp)
{
	struct _co_iocp *co_iocp = container_of(iocp, struct _co_iocp, iocp);

	/* Order is important! */
	pcs_co_event_signal(&co_iocp->op_ev);
	pcs_co_event_signal(co_iocp->co_ev);
}

static int pcs_co_wsa_recv(struct pcs_co_file *file, char *buf, int size, u64 offset, int *timeout, u32 flags)
{
	if (flags & CO_IO_NOWAIT) {
		WSABUF wsa_buf = {.buf = buf, .len = size};
		DWORD wsa_flags = 0, rcvd;
		if (!WSARecv((SOCKET)file->fd, &wsa_buf, 1, &rcvd, &wsa_flags, NULL, NULL))
			return rcvd;
		int err = -(int)WSAGetLastError();
		return err == -WSAEWOULDBLOCK ? 0 : err;
	}

	struct pcs_coroutine *co = pcs_current_co;
	int total = 0;

	while (size) {
		int rc;
		if ((rc = pcs_cancelable_prepare_wait(&co->io_wait, co->ctx)))
			return rc;

		struct _co_iocp co_iocp = {.iocp = {.done = _co_iocp_wsa_done}, .co_ev = &co->io_wait.ev};
		WSABUF wsa_buf = {.buf = buf, .len = size};
		DWORD wsa_flags = 0, rcvd;
		if (WSARecv((SOCKET)file->fd, &wsa_buf, 1, &rcvd, &wsa_flags, &co_iocp.iocp.overlapped, NULL)) {
			rc = -(int)WSAGetLastError();
			if (rc == -WSA_IO_PENDING)
				rc = _co_iocp_wsa_wait(file->fd, &co_iocp, timeout);
		} else if (file->skip_sync_notify) {
			rc = rcvd;
		} else {
			pcs_co_event_wait(&co_iocp.op_ev);
			rc = pcs_iocp_result(&co_iocp.iocp);
		}

		if (rc <= 0)
			return total ? total : rc;

		size -= rc;
		buf += rc;
		total += rc;

		if (flags & CO_IO_PARTIAL)
			break;
	}
	return total;
}

static int pcs_co_wsa_send(struct pcs_co_file *file, const char *buf, int size, u64 offset, int *timeout, u32 flags)
{
	if (flags & CO_IO_NOWAIT) {
		WSABUF wsa_buf = {.buf = (char *)buf, .len = size};
		DWORD sent;
		if (!WSASend((SOCKET)file->fd, &wsa_buf, 1, &sent, 0, NULL, NULL))
			return sent;
		int err = -(int)WSAGetLastError();
		return err == -WSAEWOULDBLOCK ? 0 : err;
	}

	struct pcs_coroutine *co = pcs_current_co;
	int total = 0;

	while (size) {
		int rc;
		if ((rc = pcs_cancelable_prepare_wait(&co->io_wait, co->ctx)))
			return rc;

		struct _co_iocp co_iocp = {.iocp = {.done = _co_iocp_wsa_done}, .co_ev = &co->io_wait.ev};
		WSABUF wsa_buf = {.buf = (char *)buf, .len = size};
		DWORD sent;
		if (WSASend((SOCKET)file->fd, &wsa_buf, 1, &sent, 0, &co_iocp.iocp.overlapped, NULL)) {
			rc = -(int)WSAGetLastError();
			if (rc == -WSA_IO_PENDING)
				rc = _co_iocp_wsa_wait(file->fd, &co_iocp, timeout);
		} else if (file->skip_sync_notify) {
			rc = sent;
		} else {
			pcs_co_event_wait(&co_iocp.op_ev);
			rc = pcs_iocp_result(&co_iocp.iocp);
		}

		if (rc < 0)
			return rc;

		BUG_ON(!rc);
		size -= rc;
		buf += rc;
		total += rc;

		if (flags & CO_IO_PARTIAL)
			break;
	}
	return total;
}

/* -------------------------------------------------------------------------------------------------- */

static void _co_iocp_file_done(struct pcs_iocp *iocp)
{
	struct _co_iocp *co_iocp = container_of(iocp, struct _co_iocp, iocp);

	pcs_co_event_signal(&co_iocp->op_ev);
}

static int pcs_co_iocp_read_file(struct pcs_co_file *file, void *buf, int size, u64 offset, int *timeout, u32 flags)
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

static int pcs_co_iocp_write_file(struct pcs_co_file *file, const void * buf, int size, u64 offset, int * timeout, u32 flags)
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

int pcs_preadv_supported(void)
{
	return 1;
}

struct _co_io_req_rwv {
	struct pcs_iocp		iocp;
	struct pcs_job		job;
	void			(*cb)(void *arg, int res);
	void			*arg;
	HANDLE			handle;
	int			size;
	int			error;
	FILE_SEGMENT_ELEMENT	seg[0];
};

static void _co_io_req_rwv_done(struct pcs_iocp *iocp)
{
	struct _co_io_req_rwv *req = container_of(iocp, struct _co_io_req_rwv, iocp);

	pcs_job_wakeup(&req->job);
}

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
	req->iocp.done = _co_io_req_rwv_done;

	*reqp = req;
	return 0;
}

static int _co_sync_io_readv(void *arg)
{
	struct _co_io_req_rwv *req = arg;

	if (!ReadFileScatter(req->handle, req->seg, req->size, NULL, &req->iocp.overlapped)) {
		int err = -(int)GetLastError();
		if (err != -ERROR_IO_PENDING) {
			req->error = err;
			pcs_iocp_send(req->job.proc, &req->iocp);
		}
	}
	return 0;
}

static void _co_io_readv_done(void *arg)
{
	struct _co_io_req_rwv *req = arg;

	int rc = req->error ? req->error : pcs_iocp_result(&req->iocp);
	if (rc == -ERROR_HANDLE_EOF || rc == -ERROR_BROKEN_PIPE)
		rc = 0;

	req->cb(req->arg, rc);
	pcs_free(req);
}

void pcs_co_file_readv_async(struct pcs_co_file *file, const struct iovec *iov, int iovcnt, u64 offset, void (*cb)(void *arg, int res), void *arg)
{
	struct pcs_process *proc = pcs_current_proc;
	struct _co_io_req_rwv* req;
	int rc;

	if ((rc = _co_io_req_rwv_alloc(iov, iovcnt, &req))) {
		cb(arg, rc);
		return;
	}

	req->iocp.overlapped.Offset = (DWORD)offset;
	req->iocp.overlapped.OffsetHigh = (DWORD)(offset >> 32);
	req->handle = file->fd;
	req->cb = cb;
	req->arg = arg;
	pcs_job_init(proc, &req->job, _co_io_readv_done, req);

	struct pcs_file_job *job = pcs_file_job_alloc(_co_sync_io_readv, req);
	pcs_file_job_submit(proc->co_io, job);
}

static int _co_sync_io_writev(void *arg)
{
	struct _co_io_req_rwv *req = arg;

	if (!WriteFileGather(req->handle, req->seg, req->size, NULL, &req->iocp.overlapped)) {
		int err = -(int)GetLastError();
		if (err != -ERROR_IO_PENDING) {
			req->error = err;
			pcs_iocp_send(req->job.proc, &req->iocp);
		}
	}
	return 0;
}

static void _co_io_writev_done(void *arg)
{
	struct _co_io_req_rwv *req = arg;

	int rc = req->error ? req->error : pcs_iocp_result(&req->iocp);

	req->cb(req->arg, rc);
	pcs_free(req);
}

void pcs_co_file_writev_async(struct pcs_co_file *file, const struct iovec *iov, int iovcnt, u64 offset, void (*cb)(void *arg, int res), void *arg)
{
	struct pcs_process *proc = pcs_current_proc;
	struct _co_io_req_rwv* req;
	int rc;

	if ((rc = _co_io_req_rwv_alloc(iov, iovcnt, &req))) {
		cb(arg, rc);
		return;
	}

	req->iocp.overlapped.Offset = (DWORD)offset;
	req->iocp.overlapped.OffsetHigh = (DWORD)(offset >> 32);
	req->handle = file->fd;
	req->cb = cb;
	req->arg = arg;
	pcs_job_init(proc, &req->job, _co_io_writev_done, req);

	struct pcs_file_job *job = pcs_file_job_alloc(_co_sync_io_writev, req);
	pcs_file_job_submit(proc->co_io, job);
}

/* -------------------------------------------------------------------------------------------------- */

static u8 sock_can_skip_sync_notify(int sa_family)
{
	return sa_family == AF_INET ? can_skip_sync_notifications : 0;
}

static int pcs_co_connect_sa(struct sockaddr * sa, socklen_t sa_len, struct pcs_co_file ** file_out, int * timeout_p)
{
	struct sockaddr_in bind_sa;
	struct pcs_coroutine *co = pcs_current_co;
	pcs_sock_t fd;
	int err;

	while (1) {
		fd = socket(sa->sa_family, SOCK_STREAM, 0);
		if (!pcs_sock_invalid(fd))
			break;

		int err = pcs_sock_errno();
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
			err = _co_iocp_wsa_wait((HANDLE)fd, &co_iocp, timeout_p);
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
		  struct pcs_co_file ** file_out, int * timeout_p)
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

		int err = pcs_sock_errno();
		if (pcs_fd_gc_on_error(pcs_current_proc, err, PCS_GC_FD_ON_ACCEPT) <= 0)
			return -err;
	}

	if ((err = pcs_cancelable_prepare_wait(&co->io_wait, co->ctx)))
		goto fail;

	struct _co_iocp co_iocp = {.iocp = {.done = _co_iocp_wsa_done}, .co_ev = &co->io_wait.ev};
	if (!pcs_acceptex((SOCKET)listen->fd, accepted_sock, &buf[0], 0, sizeof(buf[0]), sizeof(buf[1]), NULL, &co_iocp.iocp.overlapped)) {
		err = -(int)WSAGetLastError();
		if (err == -WSA_IO_PENDING)
			err = _co_iocp_wsa_wait(listen->fd, &co_iocp, timeout_p);
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

static struct pcs_co_file *pcs_co_file_alloc(pcs_fd_t fd, struct pcs_co_file_ops *ops)
{
	struct pcs_co_file *file = pcs_xzmalloc(sizeof(*file));

	file->ops = ops;
	file->fd = fd;

#ifdef __WINDOWS__
	pcs_iocp_attach(pcs_current_proc, fd, file);
#endif

	return file;
}

struct pcs_co_file *pcs_co_file_alloc_regular(pcs_fd_t fd)
{
	return pcs_co_file_alloc(fd, &pcs_co_file_ops);
}

int pcs_co_file_close(struct pcs_co_file *file)
{
	if (!file)
		return 0;

	return file->ops->close(file);
}

// ------------------------------------------------------------------------------------------------

/* TODO: kill timeout_p argument also... everything to be done via context... */
int pcs_co_io_wait_cancellable(int *timeout_p)
{
	struct pcs_coroutine *co = pcs_current_co;
	int err;

	if ((err = pcs_cancelable_prepare_wait(&co->io_wait, co->ctx)))
		return err;

	if ((err = pcs_co_event_wait_timeout(&co->io_wait.ev, timeout_p)))
		return err;

	return pcs_context_is_canceled(co->ctx);
}

int pcs_co_io_wait_cancellable_wq(struct pcs_co_waitqueue *wq, int *timeout)
{
	pcs_co_waitqueue_add(wq);
	int res = pcs_co_io_wait_cancellable(timeout);
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

	*out_file = pcs_co_file_alloc_regular(fd);
#ifdef __WINDOWS__
	/* File opened in O_DIRECT mode can be accessed using pcs_co_file_readv_async/pcs_co_file_writev_async.
	 * Implementation of these functions requires that sync notifications are enabled */
	disable_notifications(*out_file, !(flag & O_DIRECT));
#endif
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

	*out_file = pcs_co_file_alloc_regular(fd);
	return 0;
}

/* -------------------------------------------------------------------------------------------------- */

int pcs_co_file_read(struct pcs_co_file *file, void * buf, int size, u64 offset)
{
	return file->ops->read(file, buf, size, offset, NULL, 0);
}

int pcs_co_file_write(struct pcs_co_file *file, const void * buf, int size, u64 offset)
{
	return file->ops->write(file, buf, size, offset, NULL, 0);
}

int pcs_co_file_read_ex(struct pcs_co_file *file, void * buf, int size, u64 offset, int * timeout, u32 flags)
{
	return file->ops->read(file, buf, size, offset, timeout, flags);
}

int pcs_co_file_write_ex(struct pcs_co_file *file, const void * buf, int size, u64 offset, int * timeout, u32 flags)
{
	return file->ops->write(file, buf, size, offset, timeout, flags);
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

/* -------------------------------------------------------------------------------------------------- */

static int _co_sync_io_rmdir(void * pathname)
{
	return pcs_sync_rmdir((const char *)pathname);
}

int pcs_co_rmdir(const char * pathname)
{
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_rmdir, (void *)pathname);
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


static int _co_sync_io_fsync(void * fd)
{
	return pcs_sync_fsync(*(pcs_fd_t *)fd);
}

int pcs_co_file_fsync(pcs_fd_t fd)
{
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_fsync, &fd);
}

static int _co_sync_io_fdatasync(void * fd)
{
	return pcs_sync_fdatasync(*(pcs_fd_t *)fd);
}

int pcs_co_file_fdatasync(pcs_fd_t fd)
{
	return pcs_co_filejob(pcs_current_proc->co_io, _co_sync_io_fdatasync, &fd);
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

	fd = socket(sa->sa_family, SOCK_STREAM, 0);
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

int pcs_co_accept(struct pcs_co_file *listen, PCS_NET_ADDR_T * na, struct pcs_co_file ** file_out, int * timeout_p)
{
	struct sockaddr_storage sa;
	socklen_t sa_len = sizeof(sa);
	int r;

	if ((r = pcs_co_accept_sa(listen, (struct sockaddr *)&sa, &sa_len, file_out, timeout_p)))
		return r;

	if ((r = pcs_sockaddr2netaddr(na, (struct sockaddr *)&sa))) {
		pcs_co_file_close(*file_out);
		return r;
	}

	return 0;
}

int pcs_co_connect(PCS_NET_ADDR_T * na, struct pcs_co_file ** file_out, int * timeout)
{
	struct sockaddr *sa = NULL;
	int sa_len = 0;
	int r;

	pcs_netaddr2sockaddr(na, &sa, &sa_len);
	if (sa == NULL)
		return -EAFNOSUPPORT;

	r = pcs_co_connect_sa(sa, sa_len, file_out, timeout);
	pcs_free(sa);
	return r;
}

/* -------------------------------------------------------------------------------------------------- */

#ifndef __WINDOWS__
/* generic syncronous I/O redirected to co_io thread pool */
static struct pcs_co_file_ops pcs_co_file_ops = {
	.read			= pcs_co_sync_read,
	.write			= pcs_co_sync_write,
	.close			= pcs_co_sync_close
};

static struct pcs_co_file_ops pcs_co_sock_ops = {
	.read			= pcs_co_nb_read,
	.write			= pcs_co_nb_write,
	.close			= pcs_co_nb_close
};

#else /* __WINDOWS__ */

static struct pcs_co_file_ops pcs_co_file_ops = {
	.read			= pcs_co_iocp_read_file,
	.write			= pcs_co_iocp_write_file,
	.close			= pcs_co_iocp_close_file
};

static struct pcs_co_file_ops pcs_co_sock_ops = {
	.read			= pcs_co_wsa_recv,
	.write			= pcs_co_wsa_send,
	.close			= pcs_co_wsa_close
};

#endif /* __WINDOWS__ */
