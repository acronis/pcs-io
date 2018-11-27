/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */


#include "pcs_file_job.h"
#include "log.h"

#include <syslog.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "pcs_malloc.h"

#define MAX_SYSLOG_MSG_SIZE     2048
#define SYSLOG_MAX_MSG         	48

struct syslog_msg {
	struct cd_list          list;
	int                     priority;
	char                    data[0];
};

struct pcs_syslog_logger {
	char *name;
	struct pcs_file_job_conn *fjconn;
	struct cd_list  free_list;
	struct cd_list  pending;
	struct cd_list  in_progress;
	struct pcs_file_job     *fjob;
	struct pcs_file_job     __fjob;
	int             nr_allocated;
	int		refcnt;
	int		opened;
	int		closed;
};

static void submit_syslog_file_job(struct pcs_syslog_logger *log);

static void get_logger(struct pcs_syslog_logger *l)
{
	l->refcnt++;
}

static void destroy_list(struct pcs_syslog_logger *l, struct cd_list *head)
{
	struct syslog_msg *m, *tmp;
	cd_list_for_each_entry_safe(struct syslog_msg, m, tmp, head, list) {
		BUG_ON(!l->nr_allocated);
		l->nr_allocated--;
		cd_list_del(&m->list);
		pcs_free(m);
	}
}

static void put_logger(struct pcs_syslog_logger *l)
{
	BUG_ON(!l->refcnt);
	if (--l->refcnt)
		return;

	pcs_file_job_conn_stop(l->fjconn);
	l->fjconn = NULL;
	BUG_ON(!cd_list_empty(&l->in_progress));
	destroy_list(l, &l->pending);
	destroy_list(l, &l->free_list);
	BUG_ON(l->nr_allocated);
	pcs_free(l);
}

int pcs_syslog_open(struct pcs_process *proc, const char *name, struct pcs_syslog_logger **logger)
{
	int rc;
	size_t name_len = strlen(name) + 1;
	struct pcs_syslog_logger *l = pcs_malloc(sizeof(*l) + name_len);
	if (!l)
		return -ENOMEM;

	l->name = (char*)(l+1);
	memcpy(l->name, name, name_len);
	cd_list_init(&l->free_list);
	cd_list_init(&l->pending);
	cd_list_init(&l->in_progress);
	l->fjob = 0;
	l->nr_allocated = 0;
	l->refcnt = 0;
	l->closed = l->opened = 0;

	rc = pcs_file_job_conn_start(proc, "pcs-syslog", &l->fjconn);
	if (rc) {
		pcs_free(l);
		return rc;
	}

	get_logger(l);
	*logger = l;
	return 0;
}

void pcs_syslog_close(struct pcs_syslog_logger *l)
{
	if (l->closed)
		return;

	l->closed++;
	BUG_ON(!l->fjconn);
	submit_syslog_file_job(l);
	put_logger(l);
}

static int write_syslog(void *data)
{
        struct pcs_syslog_logger *l = data;
        struct syslog_msg *m;
	if (!l->opened) {
		openlog(l->name, LOG_NDELAY, LOG_USER);
		l->opened++;
	}

        cd_list_for_each_entry(struct syslog_msg, m, &l->in_progress, list) {
                syslog(m->priority, "%s", m->data);
        }

	if (l->closed) {
		closelog();
		l->closed++;
	}

        return 0;
}

static void write_syslog_done(void *arg)
{
        struct pcs_syslog_logger *l = arg;
        struct syslog_msg *m, *tmp;
        BUG_ON(!l->fjob);
        cd_list_for_each_entry_safe(struct syslog_msg, m, tmp, &l->in_progress, list) {
                cd_list_del(&m->list);
                if (l->nr_allocated > SYSLOG_MAX_MSG) {
                        l->nr_allocated--;
                        pcs_free(m);
                } else {
                        cd_list_add(&m->list, &l->free_list);
		}
        }
        l->fjob = NULL;

        if (!cd_list_empty(&l->pending) || l->closed == 1)
                submit_syslog_file_job(l);

	put_logger(l);
}

static void submit_syslog_file_job(struct pcs_syslog_logger *log)
{
        int cnt = 0;
        struct syslog_msg *m, *tmp;
	if (log->fjob)
		return;

        log->fjob = &log->__fjob;
        cd_list_for_each_entry_safe(struct syslog_msg, m, tmp, &log->pending, list) {
                cd_list_move_tail(&m->list, &log->in_progress);
                cnt++;
                if (cnt >= SYSLOG_MAX_MSG)
                        break;
        }

	get_logger(log);

        pcs_file_job_init(log->fjob, write_syslog, log);
	pcs_job_init(pcs_current_proc, &log->fjob->done, write_syslog_done, log);

        pcs_file_job_submit(log->fjconn, log->fjob);
}

static struct syslog_msg *get_message(struct pcs_syslog_logger *log)
{
        struct syslog_msg *m = NULL;
        if (!cd_list_empty(&log->free_list)) {
                m = cd_list_first_entry(&log->free_list, struct syslog_msg, list);
                cd_list_del(&m->list);
                return m;
        }

        if (log->nr_allocated < SYSLOG_MAX_MSG * 4 / 3) {
                m = pcs_malloc(MAX_SYSLOG_MSG_SIZE);
                if (!m)
                        return m;

		log->nr_allocated++;
                memset(m, 0, sizeof(*m));
                return m;
        }

        BUG_ON(cd_list_empty(&log->pending));
        /* too many allocated messages, reuse first pending message */
        m = cd_list_first_entry(&log->pending, struct syslog_msg, list);
        cd_list_del(&m->list);
        pcs_log(0, "overwrite syslog message");
        return m;
}

void pcs_syslog(struct pcs_syslog_logger *l, int priority, const char *fmt, ...)
{
        struct syslog_msg *m;
        va_list va;
	if (l->closed) {
		pcs_log(0, "Write to closed syslog");
		return;
	}

        va_start(va, fmt);
        m = get_message(l);
        vsnprintf(m->data, MAX_SYSLOG_MSG_SIZE - sizeof(*m), fmt, va);
        cd_list_add_tail(&m->list, &l->pending);
	/* translate pcs_log's level to syslog's priority */
	switch(priority) {
		case 0: // LOG_ERR -> LOG_ERR
			m->priority = 3;
			break;
		case 1: // LOG_WARN -> LOG_WARNING
			m->priority = 4;
			break;
		case 2: // LOG_INFO -> LOG_INFO
			m->priority = 6;
			break;
		default: // other -> LOG_DEBUG
			m->priority = 7;
			break;
	}

        m->priority = priority;
        submit_syslog_file_job(l);
}
