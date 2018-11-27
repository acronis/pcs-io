/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_upipe.h"
#include "pcs_co_io.h"
#include "pcs_co_locks.h"
#include "pcs_context.h"
#include "pcs_malloc.h"
#include "bug.h"

#ifndef __WINDOWS__
#include <errno.h>
#endif

struct upipe_req {
	u8			*buf;
	int			size;
	int			flags;
};

struct upipe {
	struct pcs_co_file	in_file;
	struct pcs_co_file	out_file;

	struct pcs_co_mutex	mtx;
	struct pcs_co_cond	cond;

	struct upipe_req	*in_req;
	struct upipe_req	*out_req;

	u32			in_file_dead : 1;
	u32			out_file_dead : 1;

	u32			buf_sz;
	u32			buf_pos;
	u32			buf_used;
	u8			buf[0];
};

static int out_upipe_write(struct pcs_co_file *file, const void *buf, int size, u64 offset, int *timeout, u32 flags)
{
	BUG_ON(timeout);

	if (!pcs_in_coroutine()) {
		BUG_ON(!(flags & CO_IO_NOWAIT));
		return 0;
	}

	struct upipe *u = container_of(file, struct upipe, out_file);

	pcs_co_mutex_lock(&u->mtx);
	BUG_ON(u->out_file_dead);
	BUG_ON(u->out_req);

	int res = pcs_co_ctx_is_canceled();
	if (res)
		goto done;

	if (u->in_file_dead) {
		res = -PCS_CO_PIPE;
		goto done;
	}

	if (size <= 0)
		goto done;

	struct upipe_req *in_req = u->in_req;
	if (in_req) {
		int len = in_req->size < size ? in_req->size : size;
		memcpy(in_req->buf, buf, len);
		in_req->buf += len;
		in_req->size -= len;
		buf = (const u8 *)buf + len;
		size -= len;
		res += len;
		if (!in_req->size)
			u->in_req = NULL;
		if (!in_req->size || (in_req->flags & CO_IO_PARTIAL))
			pcs_co_cond_signal(&u->cond);
		if (!size)
			goto done;
	}

	int buf_free = u->buf_sz - u->buf_used;
	if (size > buf_free && ((flags & CO_IO_NOWAIT) || ((flags & CO_IO_PARTIAL) && (res || buf_free)))) {
		size = buf_free;
		if (!size)
			goto done;
	}

	if (size <= buf_free) {
		if (!u->buf_used)
			u->buf_pos = 0;
		u32 pos = (u->buf_pos + u->buf_used) % u->buf_sz;
		int len = u->buf_sz - pos;
		if (len < size) {
			memcpy(u->buf + pos, buf, len);
			buf = (const u8 *)buf + len;
			size -= len;
			res += len;
			u->buf_used += len;
			pos = 0;
		}

		memcpy(u->buf + pos, buf, size);
		res += size;
		u->buf_used += size;
		goto done;
	}

	struct upipe_req req = {.buf = (u8 *)buf, .size = size, .flags = flags};
	u->out_req = &req;
	int rc = pcs_co_cond_wait_cancelable(&u->cond);
	if (u->out_req == &req)
		u->out_req = NULL;
	if (rc) {
		res = rc;
		goto done;
	}

	res += size - req.size;

	if ((flags & CO_IO_PARTIAL) ? !res : req.size) {
		BUG_ON(!u->in_file_dead);
		res = pcs_co_ctx_is_canceled();
		if (!res)
			res = -PCS_CO_PIPE;
	}

done:
	pcs_co_mutex_unlock(&u->mtx);
	return res;
}

static int in_upipe_read(struct pcs_co_file *file, void *buf, int size, u64 offset, int *timeout, u32 flags)
{
	BUG_ON(timeout);

	if (!pcs_in_coroutine()) {
		BUG_ON(!(flags & CO_IO_NOWAIT));
		return 0;
	}

	struct upipe *u = container_of(file, struct upipe, in_file);

	pcs_co_mutex_lock(&u->mtx);
	BUG_ON(u->in_file_dead);
	BUG_ON(u->in_req);

	int res = pcs_co_ctx_is_canceled();
	if (res)
		goto done;

	if (size <= 0)
		goto done;

	while (u->buf_used) {
		u32 len = u->buf_sz - u->buf_pos;
		if (len > u->buf_used)
			len = u->buf_used;
		if (len > size)
			len = size;
		memcpy(buf, u->buf + u->buf_pos, len);
		buf = (u8 *)buf + len;
		size -= len;
		res += len;
		u->buf_pos = (u->buf_pos + len) % u->buf_sz;
		u->buf_used -= len;
		if (!size)
			goto done;
	}

	struct upipe_req *out_req = u->out_req;
	if (out_req) {
		int len = out_req->size < size ? out_req->size : size;
		memcpy(buf, out_req->buf, len);
		out_req->buf += len;
		out_req->size -= len;
		buf = (u8 *)buf + len;
		size -= len;
		res += len;
		if (!out_req->size)
			u->out_req = NULL;
		if (!out_req->size || (out_req->flags & CO_IO_PARTIAL))
			pcs_co_cond_signal(&u->cond);
		if (!size)
			goto done;
	}

	if ((flags & CO_IO_NOWAIT) || ((flags & CO_IO_PARTIAL) && res) || u->out_file_dead)
		goto done;

	struct upipe_req req = {.buf = buf, .size = size, .flags = flags};
	u->in_req = &req;
	int rc = pcs_co_cond_wait_cancelable(&u->cond);
	if (u->in_req == &req)
		u->in_req = NULL;
	if (rc) {
		res = rc;
		goto done;
	}

	res += size - req.size;

	if ((flags & CO_IO_PARTIAL) ? !res : req.size) {
		BUG_ON(!u->out_file_dead);
		if ((rc = pcs_co_ctx_is_canceled()))
			res = rc;
	}

done:
	pcs_co_mutex_unlock(&u->mtx);
	return res;
}

static int in_upipe_write(struct pcs_co_file *file, const void *buf, int size, u64 offset, int *timeout, u32 flags)
{
	BUG();
}

static int out_upipe_read(struct pcs_co_file *file, void *buf, int size, u64 offset, int *timeout, u32 flags)
{
	BUG();
}

static int out_upipe_close(struct pcs_co_file *file)
{
	BUG_ON(!pcs_in_coroutine());

	struct upipe *u = container_of(file, struct upipe, out_file);

	pcs_co_mutex_lock(&u->mtx);
	BUG_ON(u->out_file_dead);
	BUG_ON(u->out_req);

	u->out_file_dead = 1;

	if (u->in_file_dead) {
		pcs_free(u);
	} else {
		pcs_co_cond_signal(&u->cond);
		pcs_co_mutex_unlock(&u->mtx);
	}
	return 0;
}

static int in_upipe_close(struct pcs_co_file *file)
{
	BUG_ON(!pcs_in_coroutine());

	struct upipe *u = container_of(file, struct upipe, in_file);

	pcs_co_mutex_lock(&u->mtx);
	BUG_ON(u->in_file_dead);
	BUG_ON(u->in_req);

	u->in_file_dead = 1;

	if (u->out_file_dead) {
		pcs_free(u);
	} else {
		pcs_co_cond_signal(&u->cond);
		pcs_co_mutex_unlock(&u->mtx);
	}
	return 0;
}

static struct pcs_co_file_ops in_upipe_ops  = {
	.read	= in_upipe_read,
	.write	= in_upipe_write,
	.close	= in_upipe_close,
};

static struct pcs_co_file_ops out_upipe_ops  = {
	.read	= out_upipe_read,
	.write	= out_upipe_write,
	.close	= out_upipe_close,
};

void pcs_co_upipe(struct pcs_co_file **in_file, struct pcs_co_file **out_file, u32 buf_sz)
{
	struct upipe *u = pcs_xmalloc(sizeof(*u) + buf_sz);
	pcs_co_file_init(&u->in_file, &in_upipe_ops);
	pcs_co_file_init(&u->out_file, &out_upipe_ops);
	pcs_co_mutex_init(&u->mtx);
	pcs_co_cond_init(&u->cond, &u->mtx);
	u->in_req = NULL;
	u->out_req = NULL;
	u->in_file_dead = 0;
	u->out_file_dead = 0;
	u->buf_sz = buf_sz;
	u->buf_pos = 0;
	u->buf_used = 0;
	*in_file = &u->in_file;
	*out_file = &u->out_file;
}

/* -------------------------------------------------------------------------------------------------- */

struct duplex_upipe {
	struct pcs_co_file	file;

	struct pcs_co_file	*in_file;
	struct pcs_co_file	*out_file;
};

static int duplex_upipe_read(struct pcs_co_file *file, void *buf, int size, u64 offset, int *timeout, u32 flags)
{
	struct duplex_upipe *u = container_of(file, struct duplex_upipe, file);
	return pcs_co_file_read_ex(u->in_file, buf, size, offset, timeout, flags);
}

static int duplex_upipe_write(struct pcs_co_file *file, const void *buf, int size, u64 offset, int *timeout, u32 flags)
{
	struct duplex_upipe *u = container_of(file, struct duplex_upipe, file);
	return pcs_co_file_write_ex(u->out_file, buf, size, offset, timeout, flags);
}

static int duplex_upipe_close(struct pcs_co_file *file)
{
	struct duplex_upipe *u = container_of(file, struct duplex_upipe, file);
	pcs_co_file_close(u->in_file);
	pcs_co_file_close(u->out_file);
	pcs_free(u);
	return 0;
}

static struct pcs_co_file_ops duplex_upipe_ops  = {
	.read	= duplex_upipe_read,
	.write	= duplex_upipe_write,
	.close	= duplex_upipe_close,
};

void pcs_co_upipe_duplex(struct pcs_co_file **file1, struct pcs_co_file **file2, u32 buf_sz)
{
	struct duplex_upipe *u1 = pcs_xmalloc(sizeof(*u1));
	struct duplex_upipe *u2 = pcs_xmalloc(sizeof(*u2));
	pcs_co_file_init(&u1->file, &duplex_upipe_ops);
	pcs_co_file_init(&u2->file, &duplex_upipe_ops);
	pcs_co_upipe(&u1->in_file, &u2->out_file, buf_sz);
	pcs_co_upipe(&u2->in_file, &u1->out_file, buf_sz);
	*file1 = &u1->file;
	*file2 = &u2->file;
}
