/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_CO_IO_H_
#define _PCS_CO_IO_H_ 1

#include "pcs_sock.h"
#include "pcs_coroutine.h"

/*
 * IO routines. Use them only on non-blocking files: pipes, sockets, but
 * not on disk files. Even though formally they work on disk files, they can
 * block the thread, therefore must not be used.
 */

struct pcs_process;
struct pcs_co_file_ops;
struct pcs_stat;
struct pcs_statvfs;
struct iovec;

struct pcs_co_file {
	pcs_fd_t		fd;
	struct pcs_co_file_ops	*ops;
	void			*priv;	/* user data */
#ifdef __WINDOWS__
	u8			skip_sync_notify;
#else /* __WINDOWS__ */
	struct pcs_cancelable	reader;
	struct pcs_cancelable	writer;
	pcs_atomic_ptr_t	next;
	pcs_atomic32_t		err_mask;
#ifdef __SUN__
	pthread_mutex_t		mutex;
	int			mask;
#endif /* __SUN__ */
#endif /* __WINDOWS__ */
};

static inline pcs_fd_t pcs_co_file_fd(struct pcs_co_file *file) { return file->fd; }
static inline pcs_sock_t pcs_co_file_sock(struct pcs_co_file *file) { return (pcs_sock_t)file->fd; }

/* --------------------------------------------------------------------------------- */

#define CO_IO_PARTIAL 1	/* sock/pipe: return partial buf if available, e.g. returned value can be < size even if not closed */
#define CO_IO_NOWAIT  2	/* sock/pipe: don't wait for I/O, return what is available. Can return 0 bytes. */

struct pcs_co_file_ops {
	int (*read)(struct pcs_co_file *file, void *buf, int size, u64 offset, int *timeout, u32 flags);
	int (*write)(struct pcs_co_file *file, const void * buf, int size, u64 offset, int * timeout, u32 flags);
	int (*close)(struct pcs_co_file *file);
};

void pcs_co_file_init(struct pcs_co_file *file, struct pcs_co_file_ops *ops); /* NOTE: doesn't init @file->ioconn */
PCS_API struct pcs_co_file *pcs_co_file_alloc_regular(pcs_fd_t fd);
PCS_API struct pcs_co_file *pcs_co_file_alloc_socket(pcs_sock_t sock);

/* --------------------------------------------------------------------------------- */

#define PCS_CO_FREE_BIND 1
PCS_API int pcs_co_listen(PCS_NET_ADDR_T * na, int flags, struct pcs_co_file ** listen_out);
PCS_API int pcs_co_accept(struct pcs_co_file *listen, PCS_NET_ADDR_T * na, struct pcs_co_file ** file_out, int * timeout);

PCS_API int pcs_co_connect(PCS_NET_ADDR_T * na, struct pcs_co_file ** file_out, int * timeout);

PCS_API int pcs_co_file_open(const char * pathname, int flag, int mode, struct pcs_co_file ** out_file);
PCS_API int pcs_co_file_openat(struct pcs_co_file * dir, const char * pathname, int flag, int mode, struct pcs_co_file ** out_file);
PCS_API int pcs_co_file_close(struct pcs_co_file *file);

PCS_API int pcs_co_file_pipe(struct pcs_co_file ** in_file, struct pcs_co_file ** out_file);

/* --------------------------------------------------------------------------------- */

/* Return number of bytes or -errno */
/* NOTE: offset is ignored on socket/pipe */
PCS_API int pcs_co_file_read(struct pcs_co_file *file, void * buf, int size, u64 offset);
PCS_API int pcs_co_file_write(struct pcs_co_file *file, const void * buf, int size, u64 offset);

PCS_API int pcs_co_file_read_ex(struct pcs_co_file *file, void * buf, int size, u64 offset, int * timeout, u32 flags);
PCS_API int pcs_co_file_write_ex(struct pcs_co_file *file, const void * buf, int size, u64 offset, int * timeout, u32 flags);

/* --------------------------------------------------------------------------------- */

/* May be unsuppoted on some platforms. On Windows API is limited to files opened with O_DIRECT.
 * Result of execution (number of bytes or negative pcs error) is reported to callback */
PCS_API int pcs_preadv_supported(void);

PCS_API void pcs_co_file_readv_async(struct pcs_co_file *file, const struct iovec *iov, int iovcnt, u64 offset, void (*cb)(void *arg, int res), void *arg);
PCS_API void pcs_co_file_writev_async(struct pcs_co_file *file, const struct iovec *iov, int iovcnt, u64 offset, void (*cb)(void *arg, int res), void *arg);

/* --------------------------------------------------------------------------------- */

/* Return 0 or -errno */
PCS_API int pcs_co_file_fallocate(pcs_fd_t fd, u64 size, u64 offset);
/* Before punching holes file must be marked as sparse on Windows */
PCS_API int pcs_co_file_make_sparse(pcs_fd_t fd);
PCS_API int pcs_co_file_punch_hole(pcs_fd_t fd, u64 size, u64 offset);
PCS_API int pcs_co_file_ftruncate(pcs_fd_t fd, u64 len);
PCS_API int pcs_co_file_fsync(pcs_fd_t fd);
PCS_API int pcs_co_file_fdatasync(pcs_fd_t fd);
PCS_API int pcs_co_file_getfsize(pcs_fd_t fd, u64 * size);
PCS_API int pcs_co_mkdir(const char * pathname, int mode);
PCS_API int pcs_co_rmdir(const char * pathname);
PCS_API int pcs_co_file_unlink(const char * pathname);
PCS_API int pcs_co_file_rename(const char * oldpath, const char * newpath);
PCS_API int pcs_co_file_ioctl(pcs_fd_t fd, unsigned long int cmd, void *data);
PCS_API int pcs_co_file_lock(pcs_fd_t fd, int cmd, short int type, u64 offs, u64 len);
PCS_API int pcs_co_file_close_fd(pcs_fd_t fd);

PCS_API int pcs_co_file_stat(const char * path, int flags, struct pcs_stat * res);
PCS_API int pcs_co_file_fstat(pcs_fd_t fd, struct pcs_stat * res);

PCS_API int pcs_co_statvfs(const char * path, struct pcs_statvfs * res);
PCS_API int pcs_co_fstatvfs(pcs_fd_t fd, struct pcs_statvfs * res);

/*
  A version of pcs_co_wait_timeout() that puts a caller coroutine in a cancellable sleep. See pcs_co_io_cancel().
  If canceled, returns -PCS_CO_CANCELED, and zeroes out @timeout.
*/
PCS_API int pcs_co_io_wait_cancellable(int *timeout);
/* Add a caller coroutine as a waiter to @wq, and sleep cancellably waiting for an event. */
PCS_API int pcs_co_io_wait_cancellable_wq(struct pcs_co_waitqueue *wq, int *timeout);

void pcs_co_file_pool_free(struct pcs_process *proc);

#endif /* _PCS_CO_IO_H_ */
