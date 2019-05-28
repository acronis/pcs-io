/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_BUG_H_INCLUDED
#define _PCS_BUG_H_INCLUDED

#include "pcs_types.h"

#define BUG_ON_ENABLE

#ifndef BUG_ON_ENABLE
 #include <stdlib.h>
#endif

/*
 * Bug checking related stuff
 */

/* Bug check context structure */
struct bug_point {
	const char*		file;
	const char*		func;
	int			line;
	int			active;
	unsigned long long	hits;
};

#define BUG_POINT_INITIALIZER {__FILE__, __FUNCTION__, __LINE__, 0, 0}

#ifdef BUG_ON_ENABLE
 #define BUG()		do {pcs_bug(__FILE__, __LINE__, __FUNCTION__);} while(0)
 #define BUG_()		do {static struct bug_point bp = BUG_POINT_INITIALIZER; pcs_bug_at(&bp);} while(0)
#else
 #define BUG()		do {abort();} while(0)
 #define BUG_()		do {abort();} while(0)
#endif

extern int pcs_dbg_bugon_enable;

#define BUG_ON(cond)       do {if (unlikely(cond)) BUG_();} while(0)
#define DBG_BUG_ON(cond)   do {if (pcs_dbg_bugon_enable && (cond)) BUG();} while(0)
#define DBG_BUG()          do {if (pcs_dbg_bugon_enable) BUG();} while(0)
#ifndef _MSC_VER
  #define BUILD_BUG_ON(cond) extern void __build_bug_on_dummy(char a[1 - 2*!!(cond)])
#else
  #define BUILD_BUG_ON(cond) static_assert(!(cond), #cond)
#endif
#define CHECK_ALLOC(ptr)   do {if (unlikely(!(ptr))) pcs_err("allocation failed", __FILE__, __LINE__, __FUNCTION__);} while(0)

/* Terminate execution */
PCS_API void __noreturn pcs_bug(const char *file, int line, const char *func);

/* Same as above but may be optionally ignored */
PCS_API void pcs_bug_at(struct bug_point* bp);

/* Add bugon exception. Expected to be called at the application initialization stage only.
 * May return PCS_ERR_NOMEM on allocation failure.
 */
PCS_API int pcs_bug_ignore(const char *file, int line);

/* Accept file:line specification. May return PCS_ERR_NOMEM or PCS_ERR_INV_PARAMS errors. */
PCS_API int pcs_bug_ignore_spec(const char *spec);

/* Read PSTORAGE_DBG_BUGON environment variable and set pcs_dbg_bugon_enable accordingly */
PCS_API void pcs_dbg_bugon_init(void);

/* Abort execution gracefully terminating log and calling registerd handlers (see below) */
PCS_API void __noreturn pcs_abort(void);

#endif
