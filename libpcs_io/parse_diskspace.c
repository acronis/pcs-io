/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "parse_diskspace.h"
#include "log.h"

#ifndef ULLONG_MAX
#define ULLONG_MAX  (~0ULL)
#endif

unsigned long long parse_diskspace(const char *arg, unsigned magnitude)
{
	static const char suffixes[] = "KkMmGgTt";
	unsigned long long space;
	char *p1, *p2;

	BUG_ON(magnitude > MAGN_TB);

	space = strtoull(arg, &p1, 10);
	if (space == ULLONG_MAX) {
		fprintf(stderr, "strtoul() failed: %s\n", strerror(errno));
		return 0;
	}
	if (p1 == arg) {
		fprintf(stderr, "Invalid space: %s\n", arg);
		return 0;
	}
	if (p1[0] == '\0')
		return space;

	p2 = strchr(suffixes + magnitude * 2, p1[0]);
	if ((p1[1] != '\0') || !p2) {
		fprintf(stderr, "Invalid space suffix: %s\n", p1);
		return 0;
	}

	return space << (((p2 - suffixes) / 2 - magnitude + 1) * 10);
}

int parse_logrotate_diskspace(const char *arg, unsigned long *rotate_num, unsigned long long *rotate_size)
{
	char *ptr;
	*rotate_num = strtoul(arg, &ptr, 10);
	if (*rotate_num == ULONG_MAX) {
		fprintf(stderr, "strtoul() failed: %s\n", strerror(errno));
		return -1;
	}
	if (ptr == arg) {
		fprintf(stderr, "Invalid number of rotated files.");
		return -1;
	}
	if (ptr[0] != 'x') {
		fprintf(stderr, "Invalid delimeter.");
		return -1;
	}
	++ptr;
	*rotate_size = parse_diskspace(ptr, MAGN_B);
	if (!*rotate_size)
		return -1;
	return 0;
}
