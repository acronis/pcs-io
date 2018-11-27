/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#pragma once

#include "pcs_types.h"

struct pcs_co_file;

PCS_API void pcs_co_upipe(struct pcs_co_file **in_file, struct pcs_co_file **out_file, u32 buf_sz);
PCS_API void pcs_co_upipe_duplex(struct pcs_co_file **file1, struct pcs_co_file **file2, u32 buf_sz);
