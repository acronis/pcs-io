/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef _PARSE_SPACE_H
#define _PARSE_SPACE_H

#include "pcs_types.h"

#define MAGN_B	0
#define MAGN_KB	1
#define MAGN_MB	2
#define MAGN_GB	3
#define MAGN_TB	4

/* Parse disk space specifications with possible usage of suffixes
 * (K, M, G, T in upper and lower case). Magnitude tells what "1" means, i.e.:
 * magnitude = 0 => "1" means 1 byte, all suffixes are allowed
 * magnitude = 1 => "1" means 1 kilobyte, only M, G and T suffixes are allowed
 * magnitude = 2 => "1" means 1 megabyte, only G and T suffixes are allowed
 * magnitude = 3 => "1" means 1 gigabyte, only T suffix is allowed
 */
PCS_API unsigned long long parse_diskspace(const char *arg, unsigned magnitude);
PCS_API int parse_logrotate_diskspace(const char *arg, unsigned long *rotate_num, unsigned long long *rotate_size);

#endif /* _PARSE_SPACE_H */
