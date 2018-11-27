/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_splice.h"
#include "pcs_process.h"
#include "pcs_malloc.h"
#include "log.h"

#ifdef HAS_LINUX_SPLICE
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ    (1024 + 7)
#endif

#define SPLICE_TMP_NAME "/dev/shm/vstorage/.pcs_splice_%lu"

static struct pcs_splice_buf * create_new_splice_buf(struct pcs_splice_pool * pool)
{
	int desc;
	struct pcs_splice_buf * b;
	char name[128];

	if (pool->total_count >= PCS_SPLICE_FD_LIMIT) {
		TRACE("Over splice fd limit");
		return NULL;
	}

	snprintf(name, sizeof(name), SPLICE_TMP_NAME, syscall(__NR_gettid));

	if (mknod(name, S_IFIFO | 0660, 0)) {
		if (errno != EEXIST) {
			TRACE("Failed mknod errno=%d", errno);
			return NULL;
		}
	}

	while (1) {
		desc = open(name, O_RDWR|O_NONBLOCK);
		if (desc >= 0)
			break;

		switch (errno) {
		case ENFILE:
		case EMFILE:
			if (pcs_fd_gc(pool->proc))
				continue;
			break;
		default:
			TRACE("Failed to open fifo; errno=%d", errno);
			return NULL;
		}
	}

	unlink(name);

	if (desc < 0)
		return NULL;

	if (fcntl(desc, F_SETPIPE_SZ, 1024*1024) < 0) {
		TRACE("Disabling splice, cannot set splice size : %d", errno);
		close(desc);
		pcs_splice_pool_disable(pool);
		return NULL;
	}

	b = pcs_xzmalloc(sizeof(*b));
	b->pool = pool;
	b->tag = 0;
	b->refcnt = 1;
	b->desc = desc;
	b->bytes = 0;
	pool->total_count++;
	return b;
}

struct pcs_splice_buf * pcs_splice_buf_alloc(struct pcs_splice_pool * pool)
{
	if (unlikely(pool->drain_fd < 0))
		return NULL;

	if (pool->free_count) {
		struct pcs_splice_buf * b = cd_list_first_entry(&pool->free_list, struct pcs_splice_buf, list);
		cd_list_del(&b->list);
		b->refcnt = 1;
		b->tag = 0;
		BUG_ON(b->bytes);
		BUG_ON(b->desc < 0);
		pool->free_count--;
		return b;
	}

	return create_new_splice_buf(pool);
}

struct pcs_splice_buf * pcs_splice_buf_clone(struct pcs_splice_buf * b)
{
	struct pcs_splice_buf * nb = pcs_splice_buf_alloc(b->pool);

	if (nb) {
		ssize_t n;

		n = tee(b->desc, nb->desc, b->bytes, SPLICE_F_NONBLOCK);
		if (n != b->bytes) {
			pcs_splice_buf_put(nb);
			return NULL;
		}
		nb->bytes = n;
	}
	return nb;
}

struct pcs_splice_buf * pcs_splice_buf_cut(struct pcs_splice_buf * b, int offset, int size)
{
	struct pcs_splice_buf * nb = pcs_splice_buf_alloc(b->pool);

	BUG_ON(offset + size > b->bytes);

	if (nb) {
		ssize_t n;

		n = tee(b->desc, nb->desc, offset + size, SPLICE_F_NONBLOCK);
		if (n != offset + size) {
			pcs_splice_buf_put(nb);
			return NULL;
		}
		nb->bytes = n;
		nb->tag = b->tag;
		if (offset) {
			n = splice(nb->desc, NULL, b->pool->drain_fd, NULL, offset, SPLICE_F_NONBLOCK);
			if (n != offset) {
				pcs_splice_buf_put(nb);
				return NULL;
			}
			nb->bytes -= n;
			nb->tag += n;
		}
	}
	return nb;
}

struct pcs_splice_buf * pcs_splice_buf_split(struct pcs_splice_buf * b, int size)
{
	struct pcs_splice_buf * nb = pcs_splice_buf_alloc(b->pool);

	BUG_ON(size >= b->bytes);

	if (nb) {
		ssize_t n;

		n = splice(b->desc, NULL, nb->desc, NULL, size, SPLICE_F_NONBLOCK);
		if (n != size) {
			pcs_splice_buf_put(nb);
			return NULL;
		}
		nb->bytes = n;
		nb->tag = b->tag;
		b->bytes -= n;
	}
	return nb;
}

int pcs_splice_buf_concat(struct pcs_splice_buf * b, struct pcs_splice_buf * b1)
{
	ssize_t n;

	n = splice(b1->desc, NULL, b->desc, NULL, b1->bytes, SPLICE_F_NONBLOCK);
	if (n < 0)
		return -errno;
	b1->bytes -= n;
	b1->tag += n;
	b->bytes += n;
	return b1->bytes;
}

int pcs_splice_buf_drain(struct pcs_splice_buf * b)
{
	while (b->bytes) {
		ssize_t n;

		n = splice(b->desc, NULL, b->pool->drain_fd, NULL, b->bytes, SPLICE_F_NONBLOCK);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			break;
		b->bytes -= n;
	}
	return 0;
}

void pcs_splice_buf_free(struct pcs_splice_buf * b)
{
	if (b->bytes) {
		if (pcs_splice_buf_drain(b)) {
			TRACE("Failed to drain splice buf errno=%d", errno);
			close(b->desc);
			b->pool->total_count--;
			pcs_free(b);
			return;
		}
	}

	cd_list_add_tail(&b->list, &b->pool->free_list);
	b->pool->free_count++;
}

static int splice_gc(void * arg)
{
	struct pcs_splice_pool * pool = arg;

	if (pool->free_count) {
		struct pcs_splice_buf * b = cd_list_first_entry(&pool->free_list, struct pcs_splice_buf, list);
		cd_list_del(&b->list);
		close(b->desc);
		pool->free_count--;
		pool->total_count--;
		pcs_free(b);
		return 1;
	}
	return 0;
}

/* Receive data from socket/pipe/chardev to splice buffer */

int pcs_splice_buf_recv(struct pcs_splice_buf * b, int fd, int size)
{
	int total = 0;

	while (size > 0) {
		ssize_t n;

		n = splice(fd, NULL, b->desc, NULL, size, SPLICE_F_NONBLOCK);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return total ? : -errno;
		}
		if (n == 0)
			break;
		size -= n;
		BUG_ON(size < 0);
		b->bytes += n;
		total += n;
	}
	return total;
}

int pcs_splice_buf_recv_packet(struct pcs_splice_buf * b, int fd, int size)
{
	ssize_t n;

	n = splice(fd, NULL, b->desc, NULL, size, SPLICE_F_NONBLOCK);
	if (n < 0)
		return -errno;
	b->bytes += n;
	return n;
}

/* Send data from splice buffer to socket/pipe/chardev */

int pcs_splice_buf_send(int fd, struct pcs_splice_buf * b, int size)
{
	int total = 0;

	while (size > 0) {
		ssize_t n;

		BUG_ON(size > b->bytes);

		n = splice(b->desc, NULL, fd, NULL, size, SPLICE_F_NONBLOCK);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return total ? : -errno;
		}
		if (n == 0)
			break;
		b->bytes -= n;
		size -= n;
		b->tag += n;
		total += n;
	}
	return total;
}

int pcs_splice_buf_send_packet(int fd, struct pcs_splice_buf * b)
{
	ssize_t n;

	n = splice(b->desc, NULL, fd, NULL, b->bytes, SPLICE_F_NONBLOCK);
	if (n < 0)
		return -errno;
	b->bytes -= n;
	return n;
}

/* Write data from splice buffer to seekable file */

int pcs_splice_buf_pwrite(int fd, off_t pos, struct pcs_splice_buf * b)
{
	int total = 0;

	while (b->bytes) {
		ssize_t n;

		n = splice(b->desc, NULL, fd, &pos, b->bytes, SPLICE_F_NONBLOCK);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return total ? : -errno;
		}
		if (n == 0)
			break;
		b->bytes -= n;
		b->tag += n;
		pos += n;
		total += n;
	}
	return total;
}

/* Read data from seekable file to splice buffer  */

int pcs_splice_buf_pread(struct pcs_splice_buf * b, int fd, off_t pos, int size)
{
	int total = 0;

	while (size > 0) {
		ssize_t n;

		n = splice(fd, &pos, b->desc, NULL, size, SPLICE_F_NONBLOCK);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return total ? : -errno;
		}
		if (n == 0)
			break;
		size -= n;
		b->bytes += n;
		pos += n;
		total += n;
	}
	return total;
}

/* Transfer data from splice buffer to user memory buffer */

int pcs_splice_buf_getbytes(struct pcs_splice_buf * b, char * buf, int size)
{
	int total = 0;

	BUG_ON(size > b->bytes);

	while (size) {
		ssize_t n;

		n = read(b->desc, buf, size);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return total ? : -errno;
		}
		if (n == 0)
			break;
		size -= n;
		b->bytes -= n;
		b->tag += n;
		buf += n;
		total += n;
	}
	return total;
}

int pcs_splice_buf_peekbytes(struct pcs_splice_buf * b, char * buf, int size, int offset)
{
	int total = 0;
	struct pcs_splice_buf * tb;

	tb = pcs_splice_buf_cut(b, offset, size);
	if (tb == NULL)
		return -1;

	while (size) {
		ssize_t n;

		n = read(tb->desc, buf, size);
		if (n < 0) {
			int err = errno;
			if (err == EINTR)
				continue;
			pcs_splice_buf_put(tb);
			return total ? : -err;
		}
		if (n == 0)
			break;
		size -= n;
		tb->bytes -= n;
		buf += n;
		total += n;
	}
	pcs_splice_buf_put(tb);
	return total;
}

int pcs_splice_buf_putbytes(struct pcs_splice_buf * b, char * buf, int size)
{
	int total = 0;

	while (size) {
		ssize_t n;

		n = write(b->desc, buf, size);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return total ? : -errno;
		}
		if (n == 0)
			break;
		size -= n;
		b->bytes += n;
		buf += n;
		total += n;
	}
	return total;
}

void pcs_splice_bufs_add(struct cd_list * bufs, struct pcs_splice_buf * sb)
{
	struct pcs_splice_buf * b;
	struct cd_list * ins = bufs;
	cd_list_for_each_entry_reverse(struct pcs_splice_buf, b, bufs, list) {
		if (sb->tag > b->tag) {
			ins = &b->list;
			break;
		}
	}
	cd_list_add(&sb->list, ins);
}

void pcs_splice_bufs_splice(struct cd_list * bufs, struct cd_list * sbufs)
{
	if (cd_list_empty(bufs)) {
		cd_list_splice(sbufs, bufs);
		return;
	}

	while (!cd_list_empty(sbufs)) {
		struct pcs_splice_buf * sb = cd_list_first_entry(sbufs, struct pcs_splice_buf, list);
		struct pcs_splice_buf * b;
		struct cd_list * ins = bufs;
		cd_list_del(&sb->list);
		cd_list_for_each_entry_reverse(struct pcs_splice_buf, b, bufs, list) {
			if (sb->tag > b->tag) {
				ins = &b->list;
				break;
			}
		}
		cd_list_add(&sb->list, ins);
	}
}

void pcs_splice_bufs_destroy(struct cd_list * bufs)
{
	while (!cd_list_empty(bufs)) {
		struct pcs_splice_buf * b = cd_list_first_entry(bufs, struct pcs_splice_buf, list);
		cd_list_del(&b->list);
		pcs_splice_buf_put(b);
	}
}

void pcs_splice_bufs_desplice(struct cd_list * bufs)
{
	while (!cd_list_empty(bufs)) {
		struct pcs_splice_buf * b = cd_list_first_entry(bufs, struct pcs_splice_buf, list);
		pcs_splice_buf_getbytes(b, (void*)b->tag, b->bytes);
		BUG_ON(b->bytes);
		cd_list_del(&b->list);
		pcs_splice_buf_put(b);
	}
}

void pcs_splice_bufs_desplice_mt(struct cd_list * bufs)
{
	struct pcs_splice_buf * b;

	cd_list_for_each_entry(struct pcs_splice_buf, b, bufs, list) {
		pcs_splice_buf_getbytes(b, (void*)b->tag, b->bytes);
		BUG_ON(b->bytes);
	}
}

void pcs_splice_bufs_range(struct cd_list * bufs, struct cd_list * range, void * p, unsigned int size)
{
	struct pcs_splice_buf * b;
	struct pcs_splice_buf * tnext;
	unsigned long start = (unsigned long)p;
	unsigned long end = start + size;

	cd_list_for_each_entry_safe(struct pcs_splice_buf, b, tnext, bufs, list) {
		if (b->tag >= end)
			break;
		if (b->tag + b->bytes <= start)
			continue;
		if (b->tag >= start && b->tag + b->bytes <= end) {
			cd_list_move_tail(&b->list, range);
			continue;
		}
		if (b->tag < start) {
			int n;
			struct pcs_splice_buf * nb = pcs_splice_buf_alloc(b->pool);
			if (nb == NULL) {
				TRACE("out of splice buffers 1");
				pcs_splice_bufs_desplice(bufs);
				pcs_splice_bufs_desplice(range);
				return;
			}
			n = splice(b->desc, NULL, nb->desc, NULL, start - b->tag, SPLICE_F_NONBLOCK);
			BUG_ON(n != start - b->tag);
			b->bytes -= n;
			nb->bytes = n;
			nb->tag = b->tag;
			b->tag = start;
			cd_list_add_tail(&nb->list, &b->list);
		}
		if (b->tag + b->bytes <= end) {
			cd_list_move_tail(&b->list, range);
			continue;
		} else {
			int n;
			struct pcs_splice_buf * nb = pcs_splice_buf_alloc(b->pool);
			if (nb == NULL) {
				TRACE("out of splice buffers 2");
				pcs_splice_bufs_desplice(bufs);
				pcs_splice_bufs_desplice(range);
				return;
			}
			n = splice(b->desc, NULL, nb->desc, NULL, end - b->tag, SPLICE_F_NONBLOCK);
			BUG_ON(n != end - b->tag);
			b->bytes -= n;
			nb->bytes = n;
			nb->tag = b->tag;
			b->tag = end;
			cd_list_add_tail(&nb->list, &b->list);
			cd_list_move_tail(&nb->list, range);
			break;
		}
	}
}

int pcs_splice_buf_vm(struct pcs_splice_buf * b, void * addr, int len)
{
	int n;
	struct iovec iov[1] = {{ .iov_base = addr, .iov_len = len }};

	n = vmsplice(b->desc, iov, 1, 0);
	if (n != len)
		return n < 0 ? -errno : -EFAULT;
	b->bytes += n;
	return 0;
}

void pcs_splice_pool_init(struct pcs_process * proc, struct pcs_splice_pool * pool, int enable)
{
	pool->proc = proc;
	cd_list_init(&pool->free_list);
	pool->free_count = 0;
	pool->total_count = 0;
	if (enable) {
		pool->drain_fd = open("/dev/null", O_WRONLY);
		BUG_ON(pool->drain_fd < 0);
	} else {
		pool->drain_fd = -1;
	}
	pcs_init_fd_user(proc, &pool->fd_user, pool, splice_gc);
}

void pcs_splice_pool_fini(struct pcs_splice_pool * pool)
{
	while (!cd_list_empty(&pool->free_list)) {
		struct pcs_splice_buf * b = cd_list_first_entry(&pool->free_list, struct pcs_splice_buf, list);
		cd_list_del(&b->list);
		close(b->desc);
		pcs_free(b);
		pool->free_count--;
		pool->total_count--;
	}
	BUG_ON(pool->free_count);
	BUG_ON(pool->total_count);
	if (pool->drain_fd >= 0) {
		close(pool->drain_fd);
		pool->drain_fd = -1;
	}
}

void pcs_splice_pool_disable(struct pcs_splice_pool * pool)
{
	if (pool->drain_fd >= 0) {
		close(pool->drain_fd);
		pool->drain_fd = -1;
	}
}

void pcs_splice_pool_permanently_disable(struct pcs_splice_pool * pool)
{
	pool->permanently_disabled = 1;
	pcs_splice_pool_disable(pool);
}

void pcs_splice_pool_enable(struct pcs_splice_pool * pool)
{
	if (pool->permanently_disabled) {
		pcs_log(LOG_INFO, "splice is permanently disabled, ignoring enable request");
		return;
	}
	if (pool->drain_fd < 0)
		pool->drain_fd = open("/dev/null", O_WRONLY);
}

#endif
