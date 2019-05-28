/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#pragma once

#include "pcs_types.h"
#include "pcs_config.h"
#include "std_list.h"

#include <stdarg.h>

struct iovec;

struct bufqueue_shbuf {
	void *buf;
	int refcnt;
	u32 size;
	struct cd_list pool;	/* for user: can be used for storing bufs in the pool  */
	void (*destruct)(struct bufqueue_shbuf *);
};

#define bufqueue_shbuf_alloc(buf, size)	TRACE_ALLOC(__bufqueue_shbuf_alloc, 1, buf, size)
PCS_API void bufqueue_shbuf_put(struct bufqueue_shbuf *shbuf);
PCS_API struct bufqueue_shbuf *bufqueue_shbuf_get(struct bufqueue_shbuf *shbuf);

struct bufqueue_iter
{
	const struct cd_list *pos;
};

struct bufqueue
{
	struct cd_list buffers;

	u32 total_size;

	void *priv;

	/* A soft limit on the size of @bq. @bq will be considered overflowed once its size exceeds @limit. */
	u32 size_limit;
	/* A threshold for notifying about space being available in @bq. While the size of @bq is above this value,
	   it will not call the write_space callback, thus not requesting more data. */
	u32 write_space_threshold;
	/* A threshold for notifying about data being available in @bq. While the size of @bq is below this value,
	   it will not call the data_ready callback, thus not requesting the reader to consume the data. */
	u32 data_ready_threshold;

	u32 is_shutdown : 1;

	/* A function to call when the size of the bufqueue drops below @write_space_threshold. */
	void (*write_space)(struct bufqueue *bq);
	/* A function to call when the size of the bufqueue becomes @data_ready_threshold or greater. */
	void (*data_ready)(struct bufqueue *bq);

	/* The minimum size of a buffer allocated internally by bufqueue_put_copy().
	   Subsequent calls to bufqueue_put_copy() will first use preallocated space,
	   then allocate new buffers, if needed. */
	u32 prealloc_size;
};

/* Initialise the bufqueue @bq. */
PCS_API void bufqueue_init(struct bufqueue *bq);


/* Append the buffer @data to the queue @bq. The queue will own the memory block. */
#define bufqueue_put(bq, data, size)			TRACE_ALLOC(__bufqueue_put, 1, bq, data, size)
/* Append the content of the buffer @data to the queue @bq. */
#define bufqueue_put_copy(bq, data, size)		TRACE_ALLOC(__bufqueue_put_copy, 1, bq, data, size)

/* Append part of shared buffer, i.e. shbuf->buf <= data <= data+size <= shbuf->buf+shbuf->size */
#define bufqueue_put_shbuf(bq, shbuf, data, size)	TRACE_ALLOC(__bufqueue_put_shbuf, 1, bq, shbuf, data, size)

/* Append reference to the buffer @data to the queue @bq. */
#define bufqueue_put_reference(bq, data, size)		TRACE_ALLOC(__bufqueue_put_reference, 1, bq, data, size)
/* Copy content of all buffers added by bufqueue_put_reference(). */
#define bufqueue_copy_referenced(bq)			TRACE_ALLOC(__bufqueue_copy_referenced, 1, bq)
/*
   bufqueue_put_reference() may be used to present several user-allocated
   buffers as a bufqueue without copying their content and without transfering
   the ownership of those buffers to a bufqueue. For example:

	void example1(struct bufqueue *bq, const void *buf, u32 size)
	{
		bufqueue_put_reference(bq, buf, size);
		while (bufqueue_get_size(buf) >= CHUNK_SIZE)) {
			void *chunk = malloc(CHUNK_SIZE);
			u32 n = bufqueue_get_copy(bq, chunk, CHUNK_SIZE);
			process(chunk);
		}
		bufqueue_copy_referenced(bq);
	}

	void example2(const void *buf, u32 size)
	{
		struct header header = {.size = size};
		struct bufqueue bq;
		bufqueue_init(&bq);
		bufqueue_put_reference(&bq, &header, sizeof(header));
		bufqueue_put_reference(&bq, buf, size);
		process(&bq);
		bufqueue_clear(&bq);
	}
*/

/* Prepend the content of @src to @dst, and clear @src. */
PCS_API void bufqueue_splice_head(struct bufqueue *src, struct bufqueue *dst);
/* Append the content of @src to @dst, and clear @src. If @src is shut down, then shut down @dst as well. */
PCS_API void bufqueue_splice_tail(struct bufqueue *src, struct bufqueue *dst);

/* Move @size bytes from the head of @src to the tail of @dst. */
#define bufqueue_move(dst, src, size)	TRACE_ALLOC(__bufqueue_move, 1, dst, src, size)

/* Get the length of @bq in bytes. */
static inline u32 bufqueue_get_size(const struct bufqueue *bq)
{
	return bq->total_size;
}

/* Check whether @bq is empty. */
static inline int bufqueue_empty(const struct bufqueue *bq)
{
	return bq->total_size == 0;
}

static inline int bufqueue_empty_unsafe(const struct bufqueue *bq) __no_sanitize_thread
{
	return bq->total_size == 0;
}

/* Check whether the current size of @bq is above the soft size limit. */
static inline int bufqueue_no_space(const struct bufqueue *bq)
{
	return bq->total_size >= bq->size_limit;
}

/**
   Retrieve @size bytes from the head of the queue @bq, and copy them into the buffer @data.
   The call advances the current position of @bq. If @bq contains fewer bytes than requested,
   then copy as many bytes as @bq contains.

   \param @bq the buffer queue
   \param @data the destination buffer
   \param @size how many bytes to retrieve
   \returns the number of bytes actually retrieved from @bq
 */
PCS_API u32 bufqueue_get_copy(struct bufqueue *bq, void *data, u32 size);

/**
   Retrieve bytes from the head of the queue @bq, and copy them into the buffers from @iov.
   The call advances the current position of @bq. If @bq contains fewer bytes than requested,
   then copy as many bytes as @bq contains.

   \param @bq the buffer queue
   \param @iovcnt number of destination buffers
   \param @iov list of destination buffers
   \returns the number of bytes actually retrieved from @bq
 */
PCS_API u32 bufqueue_get_copy_iovec(struct bufqueue *bq, int iovcnt, struct iovec *iov);

/**
 * Retrieve @size bytes from head of the queue @bq.
 * If continous shared buffer available then reference (counted) to it is returned in shbuf and
 *   @data pointer to the current position in shbuf.
 * If shared buffer can't be returned for some reason, then NULL is returned in @shbuf and @data.
 */
PCS_API void bufqueue_get_shbuf(struct bufqueue *bq, struct bufqueue_shbuf **shbuf, void **data, u32 size);

/**
 * Retrieve @size bytes from head of the queue @bq.
 * If continous shared buffer available then reference (counted) to it is returned in shbuf and
 *   @data pointer to the current position in shbuf.
 * If shared buffer can't be returned for some reason, then NULL is returned in @shbuf and @data.
 * The call leaves the current position of @bq unchanged.
 */
PCS_API void bufqueue_peek_shbuf(struct bufqueue *bq, struct bufqueue_shbuf **shbuf, void **data, u32 size);

/**
   Retrieve the pointer to the maximal contiguous block starting at the current position of @bq,
   and the size of it. The call leaves the current position of @bq unchanged.

   \param @bq the buffer queue
   \param @data (output) the pointer to the initial maximal contiguous block of @bq;
   will be set to NULL if @bq is empty
   \returns the length of the maximal contiguous block starting at the current position of @bq.
 */
PCS_API u32 bufqueue_peek(struct bufqueue *bq, void **data);

/**
   Retrieve the pointer to the maximal contiguous block starting at the @offset,
   and the size of it. The call leaves the current position of @bq unchanged.

   \param @bq the buffer queue
   \param @offset the starting offset of a range
   \param @data (output) the pointer to the initial maximal contiguous block of @bq;
   will be set to NULL if @bq is empty
   \param @iter (optional, output) iterator for use by bufqueue_peek_next()
   \returns the length of the maximal contiguous block starting at the current position of @bq.
 */
PCS_API u32 bufqueue_peek_at(const struct bufqueue *bq, u32 offset, void **data, struct bufqueue_iter *iter);

/**
   Retrieve the pointer to the next contiguous block,
   and the size of it. The call leaves the current position of @bq unchanged.

   \param @bq the buffer queue
   \param @data (output) the pointer to the initial maximal contiguous block of @bq;
   will be set to NULL if @bq is empty
   \param @iter iterator, its value is updated by the call
   \returns the length of the maximal contiguous block starting at the current position of @bq.
 */
PCS_API u32 bufqueue_peek_next(const struct bufqueue *bq, void **data, struct bufqueue_iter *iter);

/**
   Retrieve the pointers to @iovcnt maximal contiguous block starting at @offset,
   and the size of them. The call leaves the current position of @bq unchanged.

   \param @bq the buffer queue
   \param @offset the starting offset of a range
   \param @iov iovec to fill with pointers to buffers of @bq
   \param @iovcnt the length of @iov
   \param @iter (optional, output) iterator for use by bufqueue_peek_next_iov()
   \returns the number of entries filled in @iov.
 */
PCS_API int bufqueue_peek_at_iov(const struct bufqueue *bq, u32 offset, struct iovec *iov, int iovcnt, struct bufqueue_iter *iter);

/**
   Retrieve the pointers to next @iovcnt contiguous blocks, and the size of them.
   Theh call leaves the current position of @bq unchanged.

   \param @bq the buffer queue
   \param @iov iovec to fill with pointers to buffers of @bq
   \param @iovcnt the length of @iov
   \param @iter iterator, its value is updated by the call
   \returns the number of entries filled in @iov.
 */
PCS_API int bufqueue_peek_next_iov(const struct bufqueue *bq, struct iovec *iov, int iovcnt, struct bufqueue_iter *iter);

/**
   Retrieve @size bytes starting at @offset, and copy them to a buffer @data. If @bq
   contains fewer bytes than requested, then copy as many bytes as @bq contains.

   \param @bq the buffer queue
   \param @offset the starting offset of a range
   \param @how many bytes to retrieve
   \returns the number of bytes actually retrieved from @bq
 */
PCS_API u32 bufqueue_peek_range(const struct bufqueue *bq, u32 offset, u32 size, void *data);

/**
   Advance the current position of @bq by @size bytes. @size must not exceed the current
   size of @bq

   \param @bq the buffer queue
   \param @size how many bytes to remove from the head of @bq
 */
PCS_API void bufqueue_drain(struct bufqueue *bq, u32 size);

/* Mark @bq as shut down and notify both the reader and writer sides of it. */
PCS_API void bufqueue_shutdown(struct bufqueue *bq);

/* Clear the buffer queue @bq. */
PCS_API void bufqueue_clear(struct bufqueue *bq);


#define bufqueue_printf(bq, fmt, ...)	TRACE_ALLOC(__bufqueue_printf, 1, bq, fmt, ##__VA_ARGS__)
#define bufqueue_vprintf(bq, fmt, va)	TRACE_ALLOC(__bufqueue_vprintf, 1, bq, fmt, va)


struct malloc_item;

PCS_API struct bufqueue_shbuf* __bufqueue_shbuf_alloc(struct malloc_item **p_mi, const char *file, int check, void *buf, u32 size);

PCS_API void __bufqueue_put(struct malloc_item **p_mi, const char *file, int check, struct bufqueue *bq, void *data, u32 size);
PCS_API void __bufqueue_put_copy(struct malloc_item **p_mi, const char *file, int check, struct bufqueue *bq, const void *data, u32 size);

PCS_API void __bufqueue_put_shbuf(struct malloc_item **p_mi, const char *file, int check, struct bufqueue *bq, struct bufqueue_shbuf *shbuf, const void *data, u32 size);

PCS_API void __bufqueue_put_reference(struct malloc_item **p_mi, const char *file, int check, struct bufqueue *bq, const void *data, u32 size);
PCS_API void __bufqueue_copy_referenced(struct malloc_item **p_mi, const char *file, int check, struct bufqueue *bq);

PCS_API u32 __bufqueue_move(struct malloc_item **p_mi, const char *file, int check, struct bufqueue *dst, struct bufqueue *src, u32 size);

PCS_API void __bufqueue_printf(struct malloc_item **p_mi, const char *file, int check, struct bufqueue *bq, const char *fmt, ...) __printf(5, 6);
PCS_API void __bufqueue_vprintf(struct malloc_item **p_mi, const char *file, int check, struct bufqueue *bq, const char *fmt, va_list va);
