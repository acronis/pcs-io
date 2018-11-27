/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCS_SPLICE_H__
#define __PCS_SPLICE_H__ 1

#include "pcs_fd_gc.h"

#include <sys/types.h>

#ifdef __LINUX__
#if __GLIBC_PREREQ(2, 5)
#define HAS_LINUX_SPLICE
#endif
#endif

#ifdef HAS_LINUX_SPLICE

#define PCS_SPLICE_FD_LIMIT 4096

struct pcs_splice_buf
{
	struct cd_list	list;
	struct pcs_splice_pool * pool;
	unsigned long	tag;
	int		refcnt;
	unsigned int	bytes;
	int		desc;
};

struct pcs_splice_pool
{
	struct pcs_process *	proc;
	struct pcs_fd_user	fd_user;

	struct cd_list		free_list;
	int			free_count;
	int			total_count;

	int			drain_fd;
	int			permanently_disabled;
};

struct pcs_splice_buf * pcs_splice_buf_alloc(struct pcs_splice_pool * pool);
void pcs_splice_bufs_destroy(struct cd_list * bufs);
struct pcs_splice_buf * pcs_splice_buf_clone(struct pcs_splice_buf * b);
struct pcs_splice_buf * pcs_splice_buf_cut(struct pcs_splice_buf * b, int offset, int size);
struct pcs_splice_buf * pcs_splice_buf_split(struct pcs_splice_buf * b, int size);
int pcs_splice_buf_concat(struct pcs_splice_buf * b, struct pcs_splice_buf * b1);
int pcs_splice_buf_drain(struct pcs_splice_buf * b);
void pcs_splice_buf_free(struct pcs_splice_buf * b);
int pcs_splice_buf_recv(struct pcs_splice_buf * b, int fd, int size);
int pcs_splice_buf_recv_packet(struct pcs_splice_buf * b, int fd, int size);
int pcs_splice_buf_send(int fd, struct pcs_splice_buf * b, int size);
int pcs_splice_buf_send_packet(int fd, struct pcs_splice_buf * b);
int pcs_splice_buf_pwrite(int fd, off_t pos, struct pcs_splice_buf * b);
int pcs_splice_buf_pread(struct pcs_splice_buf * b, int fd, off_t pos, int size);
int pcs_splice_buf_getbytes(struct pcs_splice_buf * b, char * buf, int size);
int pcs_splice_buf_peekbytes(struct pcs_splice_buf * b, char * buf, int size, int offset);
int pcs_splice_buf_putbytes(struct pcs_splice_buf * b, char * buf, int size);
int pcs_splice_buf_vm(struct pcs_splice_buf * b, void * addr, int len);

void pcs_splice_bufs_add(struct cd_list * bufs, struct pcs_splice_buf * sb);
void pcs_splice_bufs_splice(struct cd_list * bufs, struct cd_list * sbufs);
void pcs_splice_bufs_desplice(struct cd_list * bufs);
void pcs_splice_bufs_desplice_mt(struct cd_list * bufs);
void pcs_splice_bufs_range(struct cd_list * bufs, struct cd_list * range, void * p, unsigned int size);

void pcs_splice_pool_init(struct pcs_process * proc, struct pcs_splice_pool * pool, int enable);
void pcs_splice_pool_fini(struct pcs_splice_pool * pool);
void pcs_splice_pool_disable(struct pcs_splice_pool * pool);
void pcs_splice_pool_permanently_disable(struct pcs_splice_pool * pool);
void pcs_splice_pool_enable(struct pcs_splice_pool * pool);

static inline struct pcs_splice_buf * pcs_splice_buf_get(struct pcs_splice_buf * b)
{
	b->refcnt++;
	return b;
}

static inline void pcs_splice_buf_put(struct pcs_splice_buf * b)
{
	if (--b->refcnt == 0)
		pcs_splice_buf_free(b);
}

static inline unsigned int pcs_splice_buf_bytes(struct pcs_splice_buf * b)
{
	return b->bytes;
}

static inline int pcs_splice_buf_enabled(struct pcs_splice_pool * pool)
{
	return pool->drain_fd >= 0;
}

#else /* HAS_LINUX_SPLICE */

static inline struct pcs_splice_buf * pcs_splice_buf_get(struct pcs_splice_buf * b) { return b; }
static inline void pcs_splice_buf_put(struct pcs_splice_buf * b) {}
static inline unsigned int pcs_splice_buf_bytes(struct pcs_splice_buf * b) { return 0; }
static inline int pcs_splice_buf_recv(struct pcs_splice_buf * b, int fd, int size) { return 0; }
static inline int pcs_splice_buf_send(int fd, struct pcs_splice_buf * b, int size) { return 0; }

#endif /* HAS_LINUX_SPLICE */

#endif /* __PCS_SPLICE_H__ */
