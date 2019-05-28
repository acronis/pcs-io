/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PCS_EXEC_H_
#define _PCS_EXEC_H_ 1

#include "pcs_co_locks.h"

#ifndef __WINDOWS__
#include <sys/types.h>
#endif

struct pcs_co_file;

struct pcs_exec {
	/* Options */
	u32	stdin_from_pipe	: 1;	/* redirect stdin from pipe */
	u32	stdout_to_pipe	: 1;	/* redirect stdout to pipe */
	u32	stderr_to_pipe	: 1;	/* redirect stderr to pipe */
	u32	stdout_to_log	: 1;	/* read out stdout and dump into pcs_log() */
	u32	stderr_to_log	: 1;	/* read out stderr and dump into pcs_log() */
	u32	set_sigmask	: 1;	/* set signal mask to speicified in sigmask field */
	u32	wait_completion	: 1;	/* wait for completion, no need to call pcs_execute_wait() explicitly */

	const char	*stdout_log_prefix;	/* prefix for log messages if stdout_to_log is used */
	const char	*stderr_log_prefix;	/* prefix for log messages if stderr_to_log is used */
	int		stdout_log_level;	/* log level for log messages if stdout_to_log is used */
	int		stderr_log_level;	/* log level for log messages if stderr_to_log is used */

	/* Output parameters */
	struct pcs_co_file	*stdin_pipe;	/* local pipe end if stdin_from_pipe is used */
	struct pcs_co_file	*stdout_pipe;	/* local pipe end if stdout_to_pipe is used */
	struct pcs_co_file	*stderr_pipe;	/* local pipe end if stderr_to_pipe is used */

	struct pcs_co_waitgroup	wg;		/* waitgroup to track process completion */
	int			exit_code;	/* process exit code filled by pcs_execute_wait() */

#ifdef __WINDOWS__
	DWORD		pid;		/* process ID */
#else
	sigset_t	sigmask;	/* signal maask if set_sigmask is used */
	pid_t		pid;		/* PID */
	int		exit_status;	/* process status information filled by pcs_execute_wait() */
#endif
};

PCS_API int pcs_execute(const char *const argv[], struct pcs_exec *e);
PCS_API void pcs_execute_wait(struct pcs_exec *e);

int pcs_co_file_to_log(int log_level, const char *prefix, struct pcs_co_file *file);

#endif
