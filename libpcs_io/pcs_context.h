/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCS_CONTEXT_H__
#define __PCS_CONTEXT_H__

#include "timer.h"
#include "pcs_co_locks.h"
#include "pcs_atomic.h"

#include <stdarg.h>

/*
 * Context serves basic needs to handle requests spaning across multiple co's and inspired by Golang:
 * - context can store some parameters (e.g. client ID or session ptr)
 * - context can be cancelled manually or by timeout, leading to I/O cancelation.
 * - context can be hierarchical (with different timeouts and params), thus any request which needs multiple actions to be done
 *   in parallel is easy to handle, while obeying all the timeouts. All it can be cancelled altogether with children contexts.
 *
 * Context access & synchronization rules.
 * Normally context is owned by coroutine. Children co "shares" parent context initially.
 * Shared contexts (refcnt > 1) are read-only, thus on pcs_co_create() refcnt is simply incremented.
 * However, any change in shared co context triggers allocation of personal child context.
 * Child context holds refcnt to parent, so its values won't be destructed while children exist.
 */

struct pcs_context_val {
#define PCS_CONTEXT_VAL_ERROR	1
#define PCS_CONTEXT_VAL_CLIENT	1
#define PCS_CONTEXT_VAL_CONN	2
#define PCS_CONTEXT_VAL_REQUEST	3
#define PCS_CONTEXT_VAL_USER	1000
	int		id;
	void		*val;
	void		(*destruct)(void *val);
};

struct pcs_context;
typedef void (*ctx_cancel_cb_t)(struct pcs_context *ctx);

struct pcs_context {
	struct pcs_context *parent;
	pcs_atomic32_t	refcnt;
	struct cd_list	children;	/* children contexts */
	struct cd_list	list;		/* inserted into parent->children */

	struct pcs_co_mutex mutex;	/* protects children and co_cancel_list */

	// context ID, can be used as log prefix
	char		*id;

	// values stored as array are faster to search, but limited in size
#define CONTEXT_NR_VALS	8
	struct pcs_context_val val[CONTEXT_NR_VALS];

	// deadline
	struct pcs_timer timer;

	// cancellation
	pcs_atomic32_t	canceled;
	struct cd_list	cancel_list;	/* list of struct pcs_cancelable */
	ctx_cancel_cb_t	cancel_cb;
};

/* ------------------------------------------------------------------------------------------------- */
/* Low-level API for manipulating contexts */
/* ------------------------------------------------------------------------------------------------- */

PCS_API struct pcs_context *pcs_context_alloc(void);
PCS_API struct pcs_context *pcs_context_alloc_child(struct pcs_context *parent);
PCS_API struct pcs_context *pcs_context_get(struct pcs_context *ctx);
PCS_API void pcs_context_put(struct pcs_context *ctx);
PCS_API void pcs_context_cancel(struct pcs_context *ctx);

PCS_API __must_check struct pcs_context * pcs_context_set_value(struct pcs_context *ctx, int id, void *val, void (*destruct)(void *val));
PCS_API void *pcs_context_get_value(const struct pcs_context *ctx, int id);
PCS_API __must_check struct pcs_context * pcs_context_set_timeout(struct pcs_context *ctx, int timeout);
PCS_API __must_check struct pcs_context * pcs_context_set_cancel_cb(struct pcs_context *ctx, ctx_cancel_cb_t cb);
PCS_API __must_check struct pcs_context * pcs_context_set_id(struct pcs_context *ctx, const char *fmt, ...) __printf(2, 3);
PCS_API __must_check struct pcs_context * pcs_context_vset_id(struct pcs_context *ctx, const char *fmt, va_list va);
PCS_API const char *pcs_context_get_id(const struct pcs_context *ctx);

static inline int pcs_context_is_canceled(struct pcs_context *ctx)
{
	return ctx ? pcs_atomic32_load(&ctx->canceled) : 0;
}

/* ------------------------------------------------------------------------------------------------- */
/* High-level API for manipulating context stored in co */
/* ------------------------------------------------------------------------------------------------- */

/* Set new context associated with co. Normally not needed as below functions allocate context automatically,
 * however can be used to reset existing context to brand new one. */
PCS_API void pcs_co_init_ctx(void);
/* Replace current coroutine context with specified */
PCS_API void pcs_co_set_ctx(struct pcs_context *ctx);
#define pcs_current_ctx (pcs_current_co->ctx)

/* Set context ID. automatically printed in pcs_co_log() */
PCS_API void pcs_co_ctx_id(const char *fmt, ...) __printf(1, 2);
PCS_API const char *pcs_co_ctx_get_id(void);
PCS_API void pcs_co_log(int level, const char *fmt, ...) __printf(2, 3);
PCS_API void pcs_ctx_log(const struct pcs_context *ctx, int level, const char *fmt, ...) __printf(3, 4);
PCS_API void pcs_ctx_vlog(const struct pcs_context *ctx, int level, const char *fmt, va_list va);

/* Set context timeout. after timeout ctx->cancelled is set, cancelled_cb() is called and all co I/O is cancelled */
PCS_API void pcs_co_ctx_set_timeout(int timeout);
PCS_API void pcs_co_ctx_set_cancel_cb(ctx_cancel_cb_t cb);

PCS_API void pcs_co_ctx_set_val(int id, void *val, void (*)(void *val));
PCS_API void *pcs_co_ctx_get_val(int id);

static inline int pcs_co_ctx_is_canceled(void)
{
	return pcs_context_is_canceled(pcs_current_ctx);
}

PCS_API int pcs_cancelable_prepare_wait(struct pcs_cancelable *cancelable, struct pcs_context *ctx);

#endif /* __PCS_CONTEXT_H__ */
