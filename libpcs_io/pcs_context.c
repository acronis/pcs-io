/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_process.h"
#include "pcs_coroutine.h"
#include "pcs_co_io.h"
#include "pcs_malloc.h"
#include "pcs_context.h"
#include "log.h"
#include "bug.h"

#include <errno.h>

static void pcs_context_cancel_ex(struct pcs_context *ctx, int err);

static int pcs_context_timeout_co(struct pcs_coroutine *co, void *arg)
{
	pcs_context_cancel_ex(pcs_current_ctx, -PCS_CO_TIMEDOUT);
	return 0;
}

static void pcs_context_timeout(void *arg)
{
	struct pcs_context *ctx = arg;

	/* should be called from co context (due to co_mutex) */
	pcs_co_create(ctx, pcs_context_timeout_co, NULL);
}

/* create empty context */
struct pcs_context *pcs_context_alloc(void)
{
	struct pcs_context *ctx = pcs_xzmalloc(sizeof(*ctx));
	pcs_atomic32_store(&ctx->refcnt, 1);
	cd_list_init(&ctx->children);
	cd_list_init(&ctx->list);
	cd_list_init(&ctx->cancel_list);
	pcs_co_mutex_init(&ctx->mutex);
	init_timer(pcs_current_proc, &ctx->timer, pcs_context_timeout, ctx);
	return ctx;
}

struct pcs_context *pcs_context_alloc_child(struct pcs_context *parent)
{
	struct pcs_context *ctx = pcs_context_alloc();

	if (!parent)
		return ctx;

	ctx->parent = pcs_context_get(parent);

	pcs_co_mutex_lock(&parent->mutex);
	cd_list_add_tail(&ctx->list, &parent->children);
	pcs_co_mutex_unlock(&parent->mutex);

	pcs_atomic32_store(&ctx->canceled, pcs_atomic32_load(&parent->canceled));	/* make sure we synchronize with pcs_context_cancel() */

	return ctx;
}

static struct pcs_context* pcs_context_cow(struct pcs_context *ctx)
{
	if (!ctx || pcs_atomic32_load(&ctx->refcnt) > 1) {
		struct pcs_context *child = pcs_context_alloc_child(ctx);
		pcs_context_put(ctx);
		ctx = child;
	}

	return ctx;
}

/* set copy of value to ctx value with given id */
__must_check struct pcs_context * pcs_context_set_value(struct pcs_context *ctx, int id, void *val, void (*destruct)(void *val))
{
	int i;
	struct pcs_context_val *cval;

	ctx = pcs_context_cow(ctx);

	for (i = 0; i < CONTEXT_NR_VALS; i++) {
		cval = &ctx->val[i];
		if (cval->id == 0 || cval->id == id)
			break;
	}

	BUG_ON(i >= CONTEXT_NR_VALS);	/* TODO: can allocate child context here in future */

	if (cval->id && cval->destruct)
		cval->destruct(cval->val);

	cval->id = id;
	cval->val = val;
	cval->destruct = destruct;

	return ctx;
}

void *pcs_context_get_value(const struct pcs_context *ctx, int id)
{
	while (ctx) {
		int i;
		for (i = 0; i < CONTEXT_NR_VALS; i++)
			if (ctx->val[i].id == id)
				return ctx->val[i].val;

		ctx = ctx->parent;
	}

	return NULL;
}

__must_check struct pcs_context * pcs_context_set_timeout(struct pcs_context *ctx, int timeout)
{
	ctx = pcs_context_cow(ctx);

	BUG_ON(timer_pending(&ctx->timer));
	mod_timer(&ctx->timer, timeout);

	return ctx;
}

__must_check struct pcs_context * pcs_context_set_cancel_cb(struct pcs_context *ctx, ctx_cancel_cb_t cb)
{
	ctx = pcs_context_cow(ctx);

	pcs_co_mutex_lock(&ctx->mutex);
	BUG_ON(ctx->cancel_cb);
	ctx->cancel_cb = cb;
	pcs_co_mutex_unlock(&ctx->mutex);

	return ctx;
}

static void pcs_context_free(struct pcs_context *ctx)
{
	del_timer_sync(&ctx->timer);

	if (ctx->parent) {
		pcs_co_mutex_lock(&ctx->parent->mutex);
		cd_list_del(&ctx->list);
		pcs_co_mutex_unlock(&ctx->parent->mutex);
	}

	int i;
	for (i = 0; i < CONTEXT_NR_VALS; i++) {
		struct pcs_context_val *val = &ctx->val[i];
		if (val->id && val->destruct)
			val->destruct(val->val);
	}

	pcs_free(ctx->id);
	ctx->parent = (struct pcs_context *)0xDEADBEAF;

	BUG_ON(!cd_list_empty(&ctx->children));
	BUG_ON(!cd_list_empty(&ctx->cancel_list));

	pcs_free(ctx);
}

struct pcs_context *pcs_context_get(struct pcs_context *ctx)
{
	if (ctx) {
		int refcnt = pcs_atomic32_fetch_and_inc(&ctx->refcnt);
		BUG_ON(refcnt <= 0);
	}
	return ctx;
}

void pcs_context_put(struct pcs_context *ctx)
{
	while (ctx) {
		int refcnt = pcs_atomic32_fetch_and_dec(&ctx->refcnt);
		BUG_ON(refcnt <= 0);
		if (refcnt > 1)
			break;

		struct pcs_context *parent = ctx->parent;
		pcs_context_free(ctx);
		ctx = parent;
	}
}

void pcs_context_cancel(struct pcs_context *ctx)
{
	pcs_context_cancel_ex(ctx, -PCS_CO_CANCELED);
}

static void pcs_context_cancel_ex(struct pcs_context *ctx, int err)
{
	if (pcs_atomic32_cas(&ctx->canceled, 0, err))
		return;

	pcs_co_mutex_lock(&ctx->mutex);

	/* cancel children first */
	struct pcs_context *child;
	cd_list_for_each_entry(struct pcs_context, child, &ctx->children, list)
		pcs_context_cancel_ex(child, err);

	struct pcs_cancelable *cancelable;
	cd_list_for_each_entry(struct pcs_cancelable, cancelable, &ctx->cancel_list, list)
		pcs_co_event_signal(&cancelable->ev);

	if (ctx->cancel_cb)
		ctx->cancel_cb(ctx);

	pcs_co_mutex_unlock(&ctx->mutex);
}

static __must_check struct pcs_context * __pcs_context_set_id(struct pcs_context *ctx, char *id)
{
	ctx = pcs_context_cow(ctx);

	pcs_free(ctx->id);
	ctx->id = id;
	return ctx;
}

__must_check struct pcs_context * pcs_context_set_id(struct pcs_context *ctx, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	char *id = pcs_xvasprintf(fmt, va);
	va_end(va);

	return __pcs_context_set_id(ctx, id);
}

__must_check struct pcs_context * pcs_context_vset_id(struct pcs_context *ctx, const char *fmt, va_list va)
{
	return __pcs_context_set_id(ctx, pcs_xvasprintf(fmt, va));
}

const char *pcs_context_get_id(const struct pcs_context *ctx)
{
	while (ctx) {
		if (ctx->id)
			return ctx->id;

		ctx = ctx->parent;
	}

	return NULL;
}

/* ------------------------------------------------------------------------------------------------- */
/* coroutine specific API */
/* ------------------------------------------------------------------------------------------------- */

void pcs_co_set_ctx(struct pcs_context *ctx)
{
	struct pcs_coroutine *co = pcs_current_co;
	struct pcs_context *old_ctx = co->ctx;

	co->ctx = pcs_context_get(ctx);
	pcs_context_put(old_ctx);
}

void pcs_co_init_ctx(void)
{
	struct pcs_context *ctx = pcs_context_alloc();
	pcs_co_set_ctx(ctx);
	pcs_context_put(ctx);
}

void pcs_co_ctx_set_timeout(int timeout)
{
	pcs_current_ctx = pcs_context_set_timeout(pcs_current_ctx, timeout);
}

void pcs_co_ctx_set_cancel_cb(ctx_cancel_cb_t cb)
{
	pcs_current_ctx = pcs_context_set_cancel_cb(pcs_current_ctx, cb);
}

void pcs_co_ctx_set_val(int id, void *val, void (*destruct)(void *val))
{
	pcs_current_ctx = pcs_context_set_value(pcs_current_ctx, id, val, destruct);
}

void *pcs_co_ctx_get_val(int id)
{
	return pcs_context_get_value(pcs_current_ctx, id);
}

void pcs_co_ctx_id(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	char *id = pcs_xvasprintf(fmt, va);
	va_end(va);

	pcs_current_ctx = __pcs_context_set_id(pcs_current_ctx, id);
}

const char *pcs_co_ctx_get_id(void)
{
	return pcs_context_get_id(pcs_current_ctx);
}

void pcs_co_log(int level, const char *fmt, ...)
{
	va_list va;

	if ((level & LOG_LEVEL_MASK) > pcs_log_level)
		return;

	va_start(va, fmt);
	pcs_ctx_vlog(pcs_current_ctx, level, fmt, va);
	va_end(va);
}

void pcs_ctx_log(const struct pcs_context *ctx, int level, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	pcs_ctx_vlog(ctx, level, fmt, va);
	va_end(va);
}

void pcs_ctx_vlog(const struct pcs_context *ctx, int level, const char *fmt, va_list va)
{
	if ((level & LOG_LEVEL_MASK) > pcs_log_level)
		return;

	pcs_valog(level, pcs_context_get_id(ctx), fmt, va);
}

int pcs_cancelable_prepare_wait(struct pcs_cancelable *cancelable, struct pcs_context *ctx)
{
	struct pcs_context *old_ctx = cancelable->ctx;
	if (old_ctx != ctx) {
		if (old_ctx) {
			pcs_co_mutex_lock(&old_ctx->mutex);
			cd_list_del(&cancelable->list);
			pcs_co_mutex_unlock(&old_ctx->mutex);
			pcs_context_put(old_ctx);
			cancelable->ctx = NULL;
		}
		if (ctx) {
			cancelable->ctx = pcs_context_get(ctx);
			pcs_co_mutex_lock(&ctx->mutex);
			cd_list_add_tail(&cancelable->list, &ctx->cancel_list);
			pcs_co_mutex_unlock(&ctx->mutex);
		}
	}
	pcs_co_event_init(&cancelable->ev);
	return pcs_context_is_canceled(ctx);
}
