/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_VCOMP_PARAMS_H
#define HSE_VCOMP_PARAMS_H

#define VCOMP_PARAM_NONE    NULL
#define VCOMP_PARAM_LZ4     "lz4"

enum vcomp_algorithm
{
	VCOMP_ALGO_NONE,
	VCOMP_ALGO_LZ4,
};

#define VCOMP_ALGO_MIN   VCOMP_ALGO_NONE
#define VCOMP_ALGO_MAX   VCOMP_ALGO_LZ4
#define VCOMP_ALGO_COUNT (VCOMP_ALGO_MAX + 1)

extern const struct compress_ops *vcomp_compress_ops[VCOMP_ALGO_COUNT];

#endif
