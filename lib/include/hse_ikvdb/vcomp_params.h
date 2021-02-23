/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_VCOMP_PARAMS_H
#define HSE_VCOMP_PARAMS_H

#include <hse_util/inttypes.h>

#define VCOMP_PARAM_NONE    "none"
#define VCOMP_PARAM_LZ4     "lz4"

#define VCOMP_PARAM_SUPPORTED  VCOMP_PARAM_NONE " " VCOMP_PARAM_LZ4
#define VCOMP_PARAM_STR_SZ 8

struct kvs_rparams;
struct compress_ops;

bool
vcomp_param_valid(const struct kvs_rparams *rp);

struct compress_ops *
vcomp_compress_ops(const struct kvs_rparams *rp);

#endif
