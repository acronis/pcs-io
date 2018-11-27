/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __LZ4_ESTIMATE_H__
#define __LZ4_ESTIMATE_H__

#include <stddef.h>
#include "pcs_types.h"

/* Estimates compressed data size. */
/* NOTE: it's only a rough estimate, do not use it for accurate output size predictions.
 * The less compressible is data the more precise estimation is, for example */
PCS_API size_t lz4_compressed_size_estimate(const char *buf, size_t buf_len);

/* Check whether data compressible or not, and ratio sets a threshold value.
 * Returns 1 if estimated compressed size <= buf_len * (1 - ratio), otherwise returns 0.
 * So ratio should be a real value in range [0.0; 1.0). The closer ratio to 1.0 the more
 * compressible data should be for the function to return 1. */
PCS_API int lz4_data_compressible(const char *buf, size_t buf_len, double ratio);

#endif /* __LZ4_ESTIMATE_H__ */
