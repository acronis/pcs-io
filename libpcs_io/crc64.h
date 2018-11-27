/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __CRC64_H__
#define __CRC64_H__

#include "pcs_types.h"

/*
 * Performance:
 * CRC64 (software only): 2000 MB/sec
 * CRC64 (Intel ISA-L library): 9200 MB/sec
 */
PCS_API uint64_t pcs_crc64(uint64_t crc, const void *buf, unsigned int len);

#endif
