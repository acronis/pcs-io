/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _USER_H
#define _USER_H

#include "pcs_types.h"

#ifndef __WINDOWS__
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#endif /* __WINDOWS__ */

int is_dir_user_valid(const char *dir);
int is_root(void);
struct passwd *get_user(const char *user);
struct group *get_group(const char *group);
int set_user_if_root(const char *user, const char *group);

#endif /* _USER_H */
