/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_shaper.h"
#include "pcs_process.h"
#include "log.h"

static void tba_shaper_start(struct pcs_tba_shaper *s)
{
	s->capacity = s->cbs;
	s->last_tick = get_abs_time_ms();
	mod_timer(&s->timer, 0);
}

static void tba_shaper_stop(struct pcs_tba_shaper *s)
{
	s->capacity = 0;
	del_timer_sync(&s->timer);
}

static void tba_shaper_timer(void *arg)
{
	struct pcs_tba_shaper *s = arg;
	const abs_time_t now = get_abs_time_ms();
	const abs_time_t elapsed = get_elapsed_time(now, s->last_tick);

	s->last_tick = now;
	s->capacity += (s->out_rate * elapsed) / 1000;
	if (s->capacity > s->cbs)
		s->capacity = s->cbs;

	mod_timer(&s->timer, PCS_SHAPER_TICK_RATE);

	if (s->wakeup_cb)
		s->wakeup_cb(s);
}

int pcs_tba_shaper_set_rate(struct pcs_tba_shaper *s, u32 out_rate, u64 cbs)
{
	if (out_rate && (out_rate < PCS_SHAPER_MIN_RATE || cbs < out_rate))
		return -1;

	if (s->cbs == cbs && s->out_rate == out_rate)
		/* don't restart shaper if params haven't changed */
		return 0;

	s->cbs = cbs;

	if (!out_rate) { /* disable shaper */
		tba_shaper_stop(s);
		/* notify watchers */
		if (s->out_rate && s->wakeup_cb)
			s->wakeup_cb(s);
	} else
		tba_shaper_start(s);

	s->out_rate = out_rate;
	return 0;
}

void pcs_tba_shaper_init(struct pcs_process *proc, struct pcs_tba_shaper *s)
{
	s->cbs = 0;
	s->capacity = 0;
	s->out_rate = 0;
	s->last_tick = 0;
	init_timer(proc, &s->timer, tba_shaper_timer, s);
}

void pcs_tba_shaper_fini(struct pcs_tba_shaper *s)
{
	tba_shaper_stop(s);
}

