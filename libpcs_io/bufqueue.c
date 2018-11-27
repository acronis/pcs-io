/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "bufqueue.h"
#include "pcs_malloc.h"
#include "bug.h"
#include "log.h"

#include <stdio.h>

struct buffer
{
	/*
                           Buffer representation
           ----------------------------------------------------
           |            |       Payload         |              |
           ----------------------------------------------------
           ^            ^                       ^              ^
          @buf        @head                @head+size   @head+size+avail
                        |                       |
                  start of payload        end of payload
	 */

	struct cd_list	node;
	void		*buf;	/* if buf points to the struct buffer itself, inline_buffer is used */
	struct bufqueue_shbuf *shbuf;
	u8		*head;
	u32		size;
	u32		avail;	/* Is zero in case of 'external' buffer (both buf and shbuf) */
	u8		inline_buffer[0];
};

static void notify_write_space(struct bufqueue *bq)
{
	if (bq->write_space && !bq->is_shutdown && bq->total_size < bq->write_space_threshold)
		bq->write_space(bq);
}

static void notify_data_ready(struct bufqueue *bq)
{
	BUG_ON(bq->is_shutdown);

	if (bq->data_ready && bq->total_size >= bq->data_ready_threshold)
		bq->data_ready(bq);
}

struct bufqueue_shbuf* __bufqueue_shbuf_alloc(struct malloc_item *mi, const char *file, int check, void *buf, u32 size)
{
	struct bufqueue_shbuf *shbuf = __pcs_malloc(mi, file, 1, sizeof(*shbuf));
	shbuf->buf = buf;
	shbuf->size = size;
	shbuf->refcnt = 1;
	shbuf->destruct = NULL;
	cd_list_init(&shbuf->pool);
	return shbuf;
}

struct bufqueue_shbuf *bufqueue_shbuf_get(struct bufqueue_shbuf *shbuf)
{
	shbuf->refcnt++;
	return shbuf;
}

void bufqueue_shbuf_put(struct bufqueue_shbuf *shbuf)
{
	if (shbuf == NULL)
		return;

	shbuf->refcnt--;
	if (shbuf->refcnt)
		return;

	if (!shbuf->destruct) {
		pcs_free(shbuf->buf);
		pcs_free(shbuf);
	} else {
		shbuf->destruct(shbuf);
	}
}

static void free_buffer(struct buffer *b)
{
	cd_list_del(&b->node);
	BUG_ON(b->buf != NULL && b->shbuf != NULL);
	if (b->shbuf)
		bufqueue_shbuf_put(b->shbuf);
	if (b->buf && b->buf != b)
		pcs_free(b->buf);
	pcs_free(b);
}

static struct buffer* alloc_buffer(struct malloc_item *mi, const char *file, struct bufqueue *bq, u32 size)
{
	BUG_ON(size == 0);

	u32 full_size = (size > bq->prealloc_size) ? size : bq->prealloc_size;
	struct buffer *b = __pcs_malloc(mi, file, 1, sizeof(*b) + full_size);
	b->buf = b;
	b->shbuf = NULL;
	b->head = b->inline_buffer;
	b->size = 0;
	b->avail = full_size;
	cd_list_add_tail(&b->node, &bq->buffers);

	return b;
}

static void build_buffer(struct malloc_item *mi, const char *file, struct bufqueue *bq, const void *data, u32 size)
{
	struct buffer *b = alloc_buffer(mi, file, bq, size);
	memcpy(b->inline_buffer, data, size);
	b->size = size;
	b->avail -= size;
}

void bufqueue_init(struct bufqueue *bq)
{
	memset(bq, 0, sizeof(*bq));
	cd_list_init(&bq->buffers);
	bq->size_limit = INT32_MAX;
	bq->write_space_threshold = INT32_MAX;
	bq->data_ready_threshold = 1;
}

void __bufqueue_put(struct malloc_item *mi, const char *file, int check, struct bufqueue *bq, void *data, u32 size)
{
	BUG_ON(bq->is_shutdown);
	BUG_ON(size > INT32_MAX - bq->total_size);

	if (!size) {
		pcs_free(data);
		return;
	}

	struct buffer *b = __pcs_malloc(mi, file, 1, sizeof(*b));
	b->buf = data;
	b->shbuf = NULL;
	b->head = data;
	b->size = size;
	b->avail = 0;

	cd_list_add_tail(&b->node, &bq->buffers);
	bq->total_size += size;

	notify_data_ready(bq);
}

void __bufqueue_put_copy(struct malloc_item *mi, const char *file, int check, struct bufqueue *bq, const void *data, u32 size)
{
	BUG_ON(bq->is_shutdown);
	BUG_ON(size > INT32_MAX - bq->total_size);

	if (!size)
		return;

	/* first try to use area in the last buffer */
	if (!cd_list_empty(&bq->buffers)) {
		struct buffer *b = cd_list_last_entry(&bq->buffers, struct buffer, node);
		if (b->avail) {
			u32 to_copy = (size < b->avail) ? size : b->avail;

			memcpy(b->head + b->size, data, to_copy);
			b->size += to_copy;
			b->avail -= to_copy;
			bq->total_size += to_copy;
			data = (const char *)data + to_copy;
			size -= to_copy;
		}
	}

	if (size) {
		build_buffer(mi, file, bq, data, size);
		bq->total_size += size;
	}

	notify_data_ready(bq);
}

void __bufqueue_put_reference(struct malloc_item *mi, const char *file, int check, struct bufqueue *bq, const void *data, u32 size)
{
	BUG_ON(bq->is_shutdown);
	BUG_ON(size > INT32_MAX - bq->total_size);

	if (!size)
		return;

	struct buffer *b = __pcs_malloc(mi, file, 1, sizeof(*b));
	b->buf = NULL;
	b->shbuf = NULL;
	b->head = (u8 *)data;
	b->size = size;
	b->avail = 0;

	cd_list_add_tail(&b->node, &bq->buffers);
	bq->total_size += size;

	notify_data_ready(bq);
}

void __bufqueue_copy_referenced(struct malloc_item *mi, const char *file, int check, struct bufqueue *bq)
{
	struct buffer *b, *tmp;
	cd_list_for_each_entry_safe(struct buffer, b, tmp, &bq->buffers, node) {
		if (b->buf || b->shbuf)
			continue;

		struct buffer *prev;
		// Copy as much as possible data to prev. buffer if any
		if (b->node.prev != &bq->buffers && (prev = cd_list_entry(b->node.prev, struct buffer, node))->avail) {
			u32 to_copy = (b->size < prev->avail) ? b->size : prev->avail;

			memcpy(prev->head + prev->size, b->head, to_copy);
			prev->size += to_copy;
			prev->avail -= to_copy;
			b->head += to_copy;
			b->size -= to_copy;

			if (!b->size) {
				free_buffer(b);
				continue;
			}
		}

		void *copy = __pcs_malloc(mi, file, 1, b->size);
		memcpy(copy, b->head, b->size);
		b->buf = copy;
		b->head = copy;
		b->avail = 0;
	}
}

void __bufqueue_put_shbuf(struct malloc_item *mi, const char *file, int check, struct bufqueue *bq, struct bufqueue_shbuf *shbuf, const void *data, u32 size)
{
	BUG_ON(bq->is_shutdown);
	BUG_ON(size > INT32_MAX - bq->total_size);

	if (!size)
		return;

	BUG_ON((ULONG_PTR)data < (ULONG_PTR)shbuf->buf || (ULONG_PTR)shbuf->buf + shbuf->size < (ULONG_PTR)data + size);
	struct buffer *b = __pcs_malloc(mi, file, 1, sizeof(*b));
	b->buf = NULL;
	b->shbuf = bufqueue_shbuf_get(shbuf);
	b->head = (u8 *)data;
	b->size = size;
	b->avail = 0;

	cd_list_add_tail(&b->node, &bq->buffers);
	bq->total_size += size;

	notify_data_ready(bq);
}

void bufqueue_splice_head(struct bufqueue *src, struct bufqueue *dst)
{
	BUG_ON(dst->is_shutdown);
	BUG_ON(src->total_size > INT32_MAX - dst->total_size);

	cd_list_splice(&src->buffers, &dst->buffers);

	dst->total_size += src->total_size;
	src->total_size = 0;

	notify_data_ready(dst);
	notify_write_space(src);
}

void bufqueue_splice_tail(struct bufqueue *src, struct bufqueue *dst)
{
	bufqueue_move(dst, src, src->total_size);
	if (src->is_shutdown)
		bufqueue_shutdown(dst);
}

u32 __bufqueue_move(struct malloc_item *mi, const char *file, int check, struct bufqueue *dst, struct bufqueue *src, u32 size)
{
	BUG_ON(dst->is_shutdown);
	BUG_ON(src->total_size > (u32)(INT32_MAX - dst->total_size));

	if (size >= src->total_size) {
		size = src->total_size;

		cd_list_splice_tail(&src->buffers, &dst->buffers);
	} else {
		u32 to_move = size;
		while (to_move) {
			BUG_ON(cd_list_empty(&src->buffers));
			struct buffer *b = cd_list_first_entry(&src->buffers, struct buffer, node);
			if (to_move < b->size) {
				build_buffer(mi, file, dst, b->head, to_move);
				b->head += to_move;
				b->size -= to_move;
				break;
			}

			cd_list_move_tail(&b->node, &dst->buffers);
			to_move -= b->size;
		}
	}

	dst->total_size += size;
	src->total_size -= size;

	notify_data_ready(dst);
	notify_write_space(src);
	return size;
}

u32 bufqueue_get_size(const struct bufqueue *bq)
{
	return bq->total_size;
}

int bufqueue_empty(const struct bufqueue *bq)
{
	return bq->total_size == 0;
}

int bufqueue_no_space(const struct bufqueue *bq)
{
	return bq->total_size >= bq->size_limit;
}

void bufqueue_peek_shbuf(struct bufqueue *bq, struct bufqueue_shbuf **shbuf, void **data, u32 size)
{
	BUG_ON(cd_list_empty(&bq->buffers));
	BUG_ON(bq->total_size < size);

	struct buffer *b = cd_list_first_entry(&bq->buffers, struct buffer, node);
	if (!b->shbuf || b->size < size) {	/* no continuous buffer available */
		*data = NULL;
		*shbuf = NULL;
	} else {
		*data = b->head;
		*shbuf = bufqueue_shbuf_get(b->shbuf);
	}
}

void bufqueue_get_shbuf(struct bufqueue *bq, struct bufqueue_shbuf **shbuf, void **data, u32 size)
{
	bufqueue_peek_shbuf(bq, shbuf, data, size);
	if (*shbuf)
		bufqueue_drain(bq, size);
}

u32 bufqueue_get_copy(struct bufqueue *bq, void *data, u32 size)
{
	char *out = data;
	while (size && !cd_list_empty(&bq->buffers)) {
		struct buffer *b = cd_list_first_entry(&bq->buffers, struct buffer, node);
		if (b->size > size) {
			memcpy(out, b->head, size);
			b->head += size;
			b->size -= size;
			out += size;
			break;
		}

		memcpy(out, b->head, b->size);
		out += b->size;
		size -= b->size;
		free_buffer(b);
	}

	u32 res = (u32)(out - (char *)data);
	bq->total_size -= res;
	notify_write_space(bq);
	return res;
}

u32 bufqueue_peek(struct bufqueue *bq, void **data)
{
	if (cd_list_empty(&bq->buffers)) {
		*data = NULL;
		return 0;
	}

	struct buffer *b = cd_list_first_entry(&bq->buffers, struct buffer, node);
	*data = b->head;
	return b->size;
}

u32 bufqueue_peek_at(const struct bufqueue *bq, u32 offset, void **data, struct bufqueue_iter *iter)
{
	struct buffer *b;
	cd_list_for_each_entry(struct buffer, b, &bq->buffers, node) {
		if (offset < b->size) {
			*data = b->head + offset;
			if (iter)
				iter->pos = b->node.next;
			return b->size - offset;
		}
		offset -= b->size;
	}

	*data = NULL;
	if (iter)
		iter->pos = &bq->buffers;
	return 0;
}

u32 bufqueue_peek_next(const struct bufqueue *bq, void **data, struct bufqueue_iter *iter)
{
	if (iter->pos == &bq->buffers) {
		*data = NULL;
		return 0;
	}

	struct buffer *b = cd_list_entry(iter->pos, struct buffer, node);
	*data = b->head;
	iter->pos = b->node.next;
	return b->size;
}

u32 bufqueue_peek_range(const struct bufqueue *bq, u32 offset, u32 size, void *data)
{
	char *out = data;
	struct buffer *b;
	cd_list_for_each_entry(struct buffer, b, &bq->buffers, node) {
		if (offset >= b->size) {
			offset -= b->size;
			continue;
		}

		u32 to_copy = b->size - offset;
		if (to_copy > size)
			to_copy = size;

		memcpy(out, b->head + offset, to_copy);
		offset = 0;
		size -= to_copy;
		out += to_copy;

		if (size == 0)
			break;
	}
	return (u32)(out - (char *)data);
}

void bufqueue_drain(struct bufqueue *bq, u32 size)
{
	u32 to_drain = size;
	while (to_drain) {
		BUG_ON(cd_list_empty(&bq->buffers));
		struct buffer *b = cd_list_first_entry(&bq->buffers, struct buffer, node);
		if (b->size > to_drain) {
			b->head += to_drain;
			b->size -= to_drain;
			break;
		}

		to_drain -= b->size;
		free_buffer(b);
	}

	bq->total_size -= size;
	notify_write_space(bq);
}

void bufqueue_shutdown(struct bufqueue *bq)
{
	if (bq->is_shutdown)
		return;

	bq->is_shutdown = 1;

	if (bq->data_ready)
		bq->data_ready(bq);
	if (bq->write_space)
		bq->write_space(bq);
}

void bufqueue_clear(struct bufqueue *bq)
{
	bufqueue_drain(bq, bq->total_size);

	BUG_ON(bq->total_size);
	BUG_ON(!cd_list_empty(&bq->buffers));
}

void __bufqueue_printf(struct malloc_item *mi, const char *file, int check, struct bufqueue *bq, const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	__bufqueue_vprintf(mi, file, 1, bq, fmt, va);
	va_end(va);
}

void __bufqueue_vprintf(struct malloc_item *mi, const char *file, int check, struct bufqueue *bq, const char *fmt, va_list va)
{
	struct buffer *b = NULL;
	char *s = NULL;
	u32 len = 0;
	int r, r0;

	if (!cd_list_empty(&bq->buffers)) {
		b = cd_list_last_entry(&bq->buffers, struct buffer, node);
		s = (char *)b->head + b->size;
		len = b->avail;
	}

	va_list va0;
	va_copy(va0, va);
	r = vsnprintf(s, len, fmt, va0);
	va_end(va0);

	/* snprintf() can fail only if @fmt is malformed */
	BUG_ON(r < 0);

	if (r >= len) {
		b = alloc_buffer(mi, file, bq, r + 1);

		r0 = vsnprintf((char *)b->head, b->avail, fmt, va);
		BUG_ON(r0 != r);
	}

	bq->total_size += r;
	b->size += r;
	b->avail -= r;
}
