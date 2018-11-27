/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#pragma once
#include "timer.h"
#include "bug.h"

/* Implementation of Token Bucket Algorithm shaper for case with single bucket */

struct pcs_tba_shaper {
	u64                     cbs;		/* committed burst size */
	u64                     capacity;       /* current capacity in units */
	u32                     out_rate;       /* outgoing rate in units per seconds */
	abs_time_t		last_tick;	/* last tick absolute time */
	struct pcs_timer        timer;
	void*			cb_arg;		/* argument for wakeup_cb */
	void (*wakeup_cb)(struct pcs_tba_shaper *s); /* called when capacity increased */
};

struct pcs_process;

#define PCS_SHAPER_TICK_RATE        10 /* milliseconds */
#define PCS_SHAPER_MIN_RATE         (1000 / PCS_SHAPER_TICK_RATE)

/* initialize shaper instance */
PCS_API void pcs_tba_shaper_init(struct pcs_process *proc, struct pcs_tba_shaper *s);

/* deinitialize shaper instance */
PCS_API void pcs_tba_shaper_fini(struct pcs_tba_shaper *s);

/* set shaper parameters:
 * out_rate - outgoing rate in units per second, out_rate must be greater than 
 * or equal to PCS_SHAPER_MIN_RATE,
 * cbs - committed burst size, must be greater than (out_rate * 1 sec) and greater than
 *       largest possible request size in units. */
PCS_API int pcs_tba_shaper_set_rate(struct pcs_tba_shaper *s, u32 out_rate, u64 cbs);

/* pass units through shaper, return non zero value if units are allowed to processing */
static inline int pcs_tba_shaper_pass(struct pcs_tba_shaper *s, u64 units)
{
	if (!s->out_rate) /* no limit to apply */
		return 1;

	BUG_ON(units > s->cbs);

	if (s->capacity < units)
		return 0;

	s->capacity -= units;
	return 1;
}

