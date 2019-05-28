/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "log.h"

#include <string.h>

#include "pcs_malloc.h"
#include "pcs_profiler.h"
#include "pcs_atexit.h"

struct bugon_exception {
	struct bugon_exception* next;
	const char*		file;
	int			line;
};

/* Bugon exceptions */
struct bugon_exception* bugon_except_list;

/* Enable debug bugons */
int pcs_dbg_bugon_enable;

void __noreturn pcs_abort(void)
{
	pcs_log_terminate();

	/* block profiler signals to avoid truncated core dumps */
	pcs_profiler_block(NULL, NULL);

	pcs_call_atexit(exit_abort);
	abort();
}

/* Terminate execution */
void pcs_bug(const char *file, int line, const char *func)
{
	pcs_err("BUG", file, line, func);
}

/* Same as above but may be optionally ignored */
void pcs_bug_at(struct bug_point* bp)
{
	if (!bp->active) {
		struct bugon_exception* x;
		bp->active = 1;
		for (x = bugon_except_list; x; x = x->next) {
			if (x->line == bp->line && !strcmp(x->file, bp->file)) {
				bp->active = -1;
				break;
			}
		}
	}
	++bp->hits;
	if (bp->active < 0) {
		pcs_log(LOG_ERR, "IGNORED BUG at %s:%d/%s() [hit number %llu]", bp->file, bp->line, bp->func, bp->hits);
		return;
	}
	pcs_bug(bp->file, bp->line, bp->func);
}

/* Add bugon exception. Expected to be called at the application initialization stage only.
 * May return PCS_ERR_NOMEM on allocation failure.
 */
int pcs_bug_ignore(const char *file, int line)
{
	struct bugon_exception* x = pcs_malloc(sizeof(*x));
	if (!x)
		return PCS_ERR_NOMEM;
	if (!(x->file = pcs_strdup(file))) {
		pcs_free(x);
		return PCS_ERR_NOMEM;
	}
	x->line = line;
	x->next = bugon_except_list;
	bugon_except_list = x;
	return 0;
}

/* Accept file:line specification. May return PCS_ERR_NOMEM or PCS_ERR_INV_PARAMS errors. */
int pcs_bug_ignore_spec(const char *spec)
{
	int res = 0;
	char *spec_copy, *sep, *eptr = 0;
	long line;
	if (!(spec_copy = pcs_strdup(spec))) {
		return PCS_ERR_NOMEM;
	}
	if (!(sep = strchr(spec_copy, ':'))) {
		res = PCS_ERR_INV_PARAMS;
		goto cleanup;
	}
	*sep++ = 0;
	line = strtol(sep, &eptr, 10);
	if (!*sep || *eptr || line <= 0) {
		res = PCS_ERR_INV_PARAMS;
		goto cleanup;
	}
	res = pcs_bug_ignore(spec_copy, line);
cleanup:
	pcs_free(spec_copy);
	return res;
}

/* Read PSTORAGE_DBG_BUGON environment variable and set pcs_dbg_bugon_enable accordingly */
void pcs_dbg_bugon_init(void)
{
	if (getenv("PSTORAGE_DBG_BUGON"))
		pcs_dbg_bugon_enable = 1;
}
