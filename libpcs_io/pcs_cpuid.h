/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#ifndef __PCS_CPUID_H__
#define __PCS_CPUID_H__

#include "pcs_types.h"

PCS_API int pcs_is_crc32_sse_supported(void);
PCS_API int pcs_is_avx2_supported(void);
PCS_API int pcs_is_aesni_supported(void);

PCS_API int pcs_cpu_is_neon_supported(void);
PCS_API int pcs_cpu_is_arm_crc_supported(void);
PCS_API int pcs_cpu_is_arm_pmull_supported(void);

#endif
