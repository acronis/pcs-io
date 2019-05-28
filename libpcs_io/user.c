/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_types.h"
#include "pcs_malloc.h"
#include "pcs_compat.h"

#ifndef __WINDOWS__
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <unistd.h>
#endif

#ifdef HAVE_LINUX_CAPS
#include <sys/prctl.h>
#include <sys/capability.h>
#endif

#include "log.h"
#include "user.h"

#ifndef __WINDOWS__
int is_dir_user_valid(const char *dir)
{
	uid_t uid;
	struct stat st;

	uid = geteuid();
	if (stat(dir, &st) < 0) {
		pcs_log(LOG_ERR, "Can't stat dir '%s': %s", dir, strerror(errno));
		return 0;
	}

	if (!S_ISDIR(st.st_mode)) {
		pcs_log(LOG_ERR, "Path %s isn't directory", dir);
		return 0;
	}

	if (uid != st.st_uid) {
		pcs_log(LOG_ERR, "Directory %s was created for a different user", dir);
		return 0;
	}
	return 1;
}

int is_root(void)
{
	return (geteuid() == 0);
}

struct passwd *get_user(const char *user)
{
	struct passwd *pw;

	errno = 0;
	pw = getpwnam(user);
	if (!pw) {
		if (errno == 0)
			pcs_log(LOG_ERR, "User '%s' not found", user);
		else
			pcs_log(LOG_ERR, "Failed to get user '%s' info: %s",
					user, strerror(errno));
		return NULL;
	}

	return pw;
}

struct group *get_group(const char *group)
{
	struct group *gr;

	errno = 0;
	gr = getgrnam(group);
	if (!gr) {
		if (errno == 0)
			pcs_log(LOG_ERR, "Group '%s' not found", group);
		else
			pcs_log(LOG_ERR, "Failed to get group '%s' info: %s",
					group, strerror(errno));
		return NULL;
	}

	return gr;
}

int set_user_if_root(const char *user, const char *group)
{
	struct passwd *pw;
	gid_t gid;

	pw = get_user(user);
	if (!pw)
		return -1;

	if (group) {
		struct group *gr = get_group(group);
		if (!gr)
			return -1;
		gid = gr->gr_gid;
	} else
		gid = pw->pw_gid;

#if defined(__MAC__)
	/* on mac, getgrouplist() takes int[], and setgroups() takes gid_t[] */
	BUILD_BUG_ON(sizeof(int) != sizeof(gid_t));
	#define GETGROUPLIST_GID_T int
#else
	#define GETGROUPLIST_GID_T gid_t
#endif
	gid_t groups[64];
	int ngroups = sizeof(groups) / sizeof(groups[0]);
	if (getgrouplist(user, gid, (GETGROUPLIST_GID_T *)groups, &ngroups) < 0) {
		pcs_log(LOG_ERR, "getgrouplist failed: %s", strerror(errno));
		return -1;
	}

	/* don't try to switch if we can't */
	if (!is_root()) {
		pcs_log(LOG_WARN, "Only root can switch users");
		return 0;
	}

#ifdef HAVE_LINUX_CAPS
	prctl(PR_SET_KEEPCAPS, 1);
#endif

	if (setgroups(ngroups, groups) < 0) {
		pcs_log(LOG_ERR, "setgroups failed: %s", strerror(errno));
		return -1;
	}

	if (setgid(gid) < 0) {
		pcs_log(LOG_ERR, "setgid failed: %s", strerror(errno));
		return -1;
	}

	if (setuid(pw->pw_uid) < 0) {
		pcs_log(LOG_ERR, "setuid failed: %s", strerror(errno));
		return -1;
	}

#ifdef HAVE_LINUX_CAPS
	struct __user_cap_header_struct caph;
	struct __user_cap_data_struct capv[2];

	caph.version = _LINUX_CAPABILITY_VERSION_3;
	caph.pid = getpid();
	memset(capv, 0, sizeof(capv));
	capv[0].effective = capv[0].permitted = capv[0].inheritable = (1 << CAP_NET_ADMIN);
	if (capset(&caph, capv))
		pcs_log(LOG_ERR, "capset : %d", errno);

	if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0)
		pcs_log(LOG_WARN, "Can't enable core dump - %s",
			strerror(errno));
#endif
	return 0;
}

#else /* __WINDOWS__ */

#include <Shlobj.h>
#include <Lmcons.h>

int is_dir_user_valid(const char *dir) { return 0; }

int is_root(void)
{
	/* available since Windows XP */
	return IsUserAnAdmin() == TRUE;
}

struct passwd *get_user(const char *user) { return NULL; }
struct group *get_group(const char *group) { return NULL; }

/* It possible to try keeping the same behavior as linux version, using LogonUser + ImpersonateLoggedOnUser API.
   But Windows security policy allows logon only (without hacking) with correct domain name and password.
   Example: https://code.msdn.microsoft.com/windowsapps/CppImpersonateUser-a0fbfd54 */
int set_user_if_root(const char *user, const char *group)
{
#if 0
	if (!is_root())
		return -1;
#endif

	WCHAR * w_user = pcs_utf8_to_utf16(user, -1);
	if (!w_user)
		return -(int)GetLastError();

	int r = -1;
	WCHAR w_curr_user[UNLEN + 1];
	/* FIXME: use _countof() for _MSC_VER >= 1400 (Visual Studio 2005) */
	DWORD len = UNLEN + 1;

	if (GetUserNameW(w_curr_user, &len)) {
		if (!_wcsnicmp(w_user, w_curr_user, len)) {
			/* success returns only if the current user is a required */
			r = 0;
		}
	}
	else
		r = -(int)GetLastError();

	pcs_free(w_user);

	return r;
}

#endif
