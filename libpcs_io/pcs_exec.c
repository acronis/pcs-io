/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_exec.h"
#include "pcs_co_io.h"
#include "pcs_compat.h"
#include "pcs_malloc.h"
#include "log.h"

#ifndef __WINDOWS__
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/wait.h>

extern char **environ;
#endif

#if !(defined(SOCK_CLOEXEC) && defined(HAVE_PIPE2) && defined(HAVE_ACCEPT4)) && !defined(__MAC__)
#define USE_EXEC_LOCK
#endif

#ifdef __WINDOWS__
static u32 need_escape(const wchar_t *s)
{
	if (*s == L'\0')
		return 1;
	do {
		if (*s == L' ' || *s == L'\t')
			return 1;
	} while (*(++s) != L'\0');
	return 0;
}

#define MAX_CMDLINE_LEN		32768

/* This function performs reverse conversion to algorithm described in
 * https://docs.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments */
static int argv_to_cmdline(const char *const argv[], wchar_t **cmdline)
{
	u32 buf_sz = 256;
	u32 len = 0;
	wchar_t *buf = pcs_xmalloc(buf_sz * sizeof(wchar_t));
	wchar_t *warg;

	for (; *argv; argv++) {
		if (!(warg = pcs_utf8_to_utf16(*argv, - 1))) {
			int rc = -(int)GetLastError();
			pcs_free(buf);
			return rc;
		}

#define PUT(c)	do { \
			if (len >= MAX_CMDLINE_LEN) \
				goto too_long; \
			if (len >= buf_sz) \
				buf = pcs_xrealloc(buf, (buf_sz *= 2) * sizeof(wchar_t)); \
			buf[len++] = (c); \
		} while (0)

		u32 escape = need_escape(warg);
		if (escape)
			PUT(L'"');

		wchar_t *p = warg;
		u32 nr_bs;
		while (*p != L'\0') {
			switch (*p) {
			case L'\\':
				nr_bs = 1;
				while (*(++p) == L'\\')
					nr_bs++;
				if (*p == L'"' || (*p == L'\0' && escape))
					nr_bs *= 2;
				do {
					PUT(L'\\');
				} while (--nr_bs);
				break;

			case L'"':
				PUT(L'\\');
				/* FALLTHROUGH */
			default:
				PUT(*p);
				p++;
			}
		}

		if (escape)
			PUT(L'"');

		PUT(argv[1] ? L' ' : L'\0');

#undef PUT

		pcs_free(warg);
	}

	*cmdline = buf;
	return 0;

too_long:
	pcs_free(warg);
	pcs_free(buf);
	return -ERROR_INVALID_PARAMETER;
}
#endif

struct to_log_arg {
	struct pcs_co_file	*file;
	int			log_level;
	char			*prefix;
	struct pcs_co_waitgroup	*wg;
};

#define MAX_LINE_LEN	4096

static void log_one_line(int level, const char *prefix, const char *buf, int len)
{
#ifdef __WINDOWS__
	if (len && buf[len - 1] == '\r')
		len--;
#endif
	pcs_log(level, "%s%.*s", prefix, len, buf);
}

int pcs_co_file_to_log(int log_level, const char *prefix, struct pcs_co_file *file)
{
	char buf[MAX_LINE_LEN];
	int buf_used = 0;
	int n;
	while ((n = pcs_co_file_read_ex(file, buf + buf_used, MAX_LINE_LEN - buf_used, CO_IO_PARTIAL)) > 0) {
		char *eol = memchr(buf + buf_used, '\n', n);
		buf_used += n;
		if (!eol) {
			if (buf_used < MAX_LINE_LEN)
				continue;

			log_one_line(log_level, prefix, buf, MAX_LINE_LEN);
			buf_used = 0;
			continue;
		}

		char *pos = buf;
		do {
			log_one_line(log_level, prefix, pos, (int)(eol - pos));
			pos = eol + 1;
			eol = memchr(pos, '\n', buf + buf_used - pos);
		} while (eol);

		memmove(buf, pos, buf + buf_used - pos);
		buf_used -= (int)(pos - buf);
	}

	if (buf_used)
		log_one_line(log_level, prefix, buf, buf_used);

	return n;
}

static int to_log_co(struct pcs_coroutine *co, void *arg)
{
	struct to_log_arg *a = arg;

	pcs_co_set_name(co, "%sto_log", a->prefix);

	pcs_co_file_to_log(a->log_level, a->prefix, a->file);
	pcs_co_file_close(a->file);
	pcs_free(a->prefix);
	pcs_co_waitgroup_done(a->wg);
	pcs_free(a);
	return 0;
}

struct exec_thread_arg {
	const char *const	*argv;
	struct pcs_exec		*e;
	struct pcs_process	*proc;
	pcs_fd_t		stdin_fd;
	pcs_fd_t		stdout_fd;
	pcs_fd_t		stderr_fd;
	int			rc;
	struct pcs_co_event	ev;
};

#ifdef __WINDOWS__
static int execute_using_create_process(struct exec_thread_arg *a, HANDLE *proc_handle)
{
	wchar_t *applicationName	= NULL;
	wchar_t *commandLine		= NULL;
	int rc;

	if (!(applicationName = pcs_utf8_to_utf16(a->argv[0], -1))) {
		rc = -(int)GetLastError();
		goto done;
	}

	if ((rc = argv_to_cmdline(a->argv, &commandLine)))
		goto done;

	STARTUPINFOW startupInfo = {
		.cb = sizeof(startupInfo),
		.dwFlags = STARTF_USESTDHANDLES,
		.hStdInput = a->stdin_fd,
		.hStdOutput = a->stdout_fd,
		.hStdError = a->stderr_fd,
	};

	PROCESS_INFORMATION processInformation;

	if (!CreateProcessW(applicationName, commandLine, NULL, NULL, TRUE, DETACHED_PROCESS, NULL, NULL, &startupInfo, &processInformation)) {
		rc = -(int)GetLastError();
		goto done;
	}

	*proc_handle = processInformation.hProcess;
	a->e->pid = processInformation.dwProcessId;
	CloseHandle(processInformation.hThread);

done:
	pcs_free(applicationName);
	pcs_free(commandLine);
	return rc;
}
#else /* __WINDOWS__ */
static int execute_using_posix_spawn(struct exec_thread_arg *a)
{
	int rc;

	posix_spawn_file_actions_t file_actions;
	if ((rc = posix_spawn_file_actions_init(&file_actions)))
		goto done;
	if ((rc = posix_spawn_file_actions_adddup2(&file_actions, a->stdin_fd, STDIN_FILENO)))
		goto destroy_file_action;
	if ((rc = posix_spawn_file_actions_adddup2(&file_actions, a->stdout_fd, STDOUT_FILENO)))
		goto destroy_file_action;
	if ((rc = posix_spawn_file_actions_adddup2(&file_actions, a->stderr_fd, STDERR_FILENO)))
		goto destroy_file_action;
	posix_spawnattr_t spawn_attr;
	if ((rc = posix_spawnattr_init(&spawn_attr)))
		goto destroy_file_action;
#ifdef __LINUX__
	int flags = POSIX_SPAWN_USEVFORK;
#elif defined(__MAC__)
	int flags = POSIX_SPAWN_CLOEXEC_DEFAULT;
#else
	int flags = 0;
#endif
	if (a->e->set_sigmask)
		flags |= POSIX_SPAWN_SETSIGMASK;
	if ((rc = posix_spawnattr_setflags(&spawn_attr, flags)))
		goto destroy_spawn_attr;
	if (a->e->set_sigmask && ((rc = posix_spawnattr_setsigmask(&spawn_attr, &a->e->sigmask))))
		goto destroy_spawn_attr;
	rc = posix_spawn(&a->e->pid, a->argv[0], &file_actions, &spawn_attr, (char **)a->argv, environ);

destroy_spawn_attr:
	posix_spawnattr_destroy(&spawn_attr);
destroy_file_action:
	posix_spawn_file_actions_destroy(&file_actions);
done:
	return -rc;
}
#endif /* __WINDOWS__ */

#if defined(__LINUX__) && defined(USE_EXEC_LOCK)
static int cloexec_supported(void)
{
	static int supported = -1;
	if (supported >= 0)
		return supported;

	int res = 0;
	int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		res = fcntl(fd, F_GETFD);
		res = res >= 0 ? res & FD_CLOEXEC : 0;
		close(fd);
	}
	supported = res;
	return res;
}

static int execute_using_fork(struct exec_thread_arg *a)
{
	pid_t pid = fork();
	if (pid < 0)
		return -errno;
	if (pid > 0) {
		a->e->pid = pid;
		return 0;
	}

	/* Child process */
	dup2(a->stdin_fd, STDIN_FILENO);
	dup2(a->stdout_fd, STDOUT_FILENO);
	dup2(a->stderr_fd, STDERR_FILENO);

	DIR *dir = opendir("/proc/self/fd");
	if (dir) {
		struct dirent *entry;
		while ((entry = readdir(dir))) {
			char *endp;
			unsigned long fd = strtoul(entry->d_name, &endp, 10);
			if (*endp == '\0' && 3 <= fd && fd <= INT_MAX)
				fcntl(fd, F_SETFD, FD_CLOEXEC);
		}
		closedir(dir);
	}

	if (a->e->set_sigmask)
		sigprocmask(SIG_SETMASK, &a->e->sigmask, NULL);

	execv(a->argv[0], (char **)a->argv);
	_exit(127);
}
#endif

static void event_signal(void *arg)
{
	pcs_co_event_signal(arg);
}

static void waitgroup_done(void *arg)
{
	pcs_co_waitgroup_done(arg);
}

static pcs_thread_ret_t exec_thread(void *arg)
{
	struct exec_thread_arg *a = arg;
	struct pcs_exec *e = a->e;
	struct pcs_process *proc = a->proc;
	int rc;

#ifdef __WINDOWS__
	HANDLE proc_handle;
	rc = execute_using_create_process(a, &proc_handle);
#else /* __WINDOWS__ */
#if defined(__LINUX__) && defined(USE_EXEC_LOCK)
	if (!cloexec_supported())
		rc = execute_using_fork(a);
	else
#endif
		rc = execute_using_posix_spawn(a);
#endif /* __WINDOWS__ */

	a->rc = rc;
	pcs_call_in_job(proc, event_signal, &a->ev);
	if (rc)
		return 0;

	/* exec_thread_arg should not be used below this point */

#ifdef __WINDOWS__
	WaitForSingleObject(proc_handle, INFINITE);
	DWORD exit_code;
	if (GetExitCodeProcess(proc_handle, &exit_code))
		e->exit_code = exit_code;
	CloseHandle(proc_handle);
#else /* __WINDOWS__ */
	pid_t pid;
	while ((pid = waitpid(e->pid, &e->exit_status, 0)) < 0 && errno == EINTR)
		/* nothing to do */;
	if (pid > 0 && WIFEXITED(e->exit_status))
		e->exit_code = WEXITSTATUS(e->exit_status);
#endif /* __WINDOWS__ */

	pcs_call_in_job(proc, waitgroup_done, &e->wg);
	return 0;
}

int pcs_execute(const char *const argv[], struct pcs_exec *e)
{
	if (!argv[0] ||
            (e->stdout_to_pipe && e->stdout_to_log) || (e->stderr_to_pipe && e->stderr_to_log) ||
	    ((e->stdin_from_pipe || e->stdout_to_pipe || e->stderr_to_pipe) && e->wait_completion)) {
#ifdef __WINDOWS__
		return -ERROR_INVALID_PARAMETER;
#else
		return -EINVAL;
#endif
	}

	struct pcs_co_file *stdin_in	= NULL;
	struct pcs_co_file *stdin_out	= NULL;
	struct pcs_co_file *stdout_in	= NULL;
	struct pcs_co_file *stdout_out	= NULL;
	struct pcs_co_file *stderr_in	= NULL;
	struct pcs_co_file *stderr_out	= NULL;
	int rc;

#ifdef USE_EXEC_LOCK
	struct pcs_co_rwlock *lock = pcs_current_proc->exec_lock;
	pcs_co_write_lock(lock);
#endif

	if (e->stdin_from_pipe)
		rc = pcs_co_file_pipe_ex(&stdin_in, &stdin_out, PCS_CO_IN_PIPE_FOR_EXEC);
	else
		rc = pcs_co_open_dev_null(O_RDONLY, &stdin_in);
	if (rc)
		goto done;

	if (e->stdout_to_pipe || e->stdout_to_log)
		rc = pcs_co_file_pipe_ex(&stdout_in, &stdout_out, PCS_CO_OUT_PIPE_FOR_EXEC);
	else
		rc = pcs_co_open_dev_null(O_WRONLY, &stdout_out);
	if (rc)
		goto done;

	if (e->stderr_to_pipe || e->stderr_to_log)
		rc = pcs_co_file_pipe_ex(&stderr_in, &stderr_out, PCS_CO_OUT_PIPE_FOR_EXEC);
	else
		rc = pcs_co_open_dev_null(O_WRONLY, &stderr_out);
	if (rc)
		goto done;

	pcs_co_waitgroup_init(&e->wg, 1);
	e->exit_code = -1;

	struct exec_thread_arg arg = {
		.argv		= argv,
		.e		= e,
		.proc		= pcs_current_proc,
		.stdin_fd	= pcs_co_file_fd(stdin_in),
		.stdout_fd	= pcs_co_file_fd(stdout_out),
		.stderr_fd	= pcs_co_file_fd(stderr_out),
	};

	pcs_thread_t thread;
	if (pcs_thread_create(&thread, NULL, exec_thread, &arg)) {
		pcs_co_waitgroup_done(&e->wg);
#ifdef __WINDOWS__
		rc = -ERROR_NO_SYSTEM_RESOURCES;
#else
		rc = -ENOMEM;
#endif
		goto done;
	}
	pthread_detach(thread);

	pcs_co_event_wait(&arg.ev);
	if ((rc = arg.rc)) {
		pcs_co_waitgroup_done(&e->wg);
		goto done;
	}

	if (e->stdout_to_log) {
		struct to_log_arg *a = pcs_xmalloc(sizeof(*a));
		a->file = stdout_in;
		stdout_in = NULL;
		a->log_level = e->stdout_log_level;
		a->prefix = e->stdout_log_prefix ? pcs_xasprintf("%s: ", e->stdout_log_prefix) : pcs_xzmalloc(1);
		a->wg = &e->wg;
		pcs_co_waitgroup_add(&e->wg, 1);
		pcs_co_create(NULL, to_log_co, a);
	}

	if (e->stderr_to_log) {
		struct to_log_arg *a = pcs_xmalloc(sizeof(*a));
		a->file = stderr_in;
		stderr_in = NULL;
		a->log_level = e->stderr_log_level;
		a->prefix = e->stderr_log_prefix ? pcs_xasprintf("%s: ", e->stderr_log_prefix) : pcs_xzmalloc(1);
		a->wg = &e->wg;
		pcs_co_waitgroup_add(&e->wg, 1);
		pcs_co_create(NULL, to_log_co, a);
	}

	e->stdin_pipe = stdin_out;
	stdin_out = NULL;
	e->stdout_pipe = stdout_in;
	stdout_in = NULL;
	e->stderr_pipe = stderr_in;
	stderr_in = NULL;

done:
	pcs_co_file_close(stdin_in);
	pcs_co_file_close(stdin_out);
	pcs_co_file_close(stdout_in);
	pcs_co_file_close(stdout_out);
	pcs_co_file_close(stderr_in);
	pcs_co_file_close(stderr_out);

#ifdef USE_EXEC_LOCK
	pcs_co_write_unlock(lock);
#endif

	if (e->wait_completion)
		pcs_execute_wait(e);

	return rc;
}

void pcs_execute_wait(struct pcs_exec *e)
{
	pcs_co_waitgroup_wait(&e->wg);
}
