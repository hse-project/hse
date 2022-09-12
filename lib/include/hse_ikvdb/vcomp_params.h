/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_VCOMP_PARAMS_H
#define HSE_VCOMP_PARAMS_H

#include <stdint.h>

#define VCOMP_PARAM_OFF "off"
#define VCOMP_PARAM_ON  "on"
#define VCOMP_PARAM_LZ4 "lz4"

enum vcomp_default {
    VCOMP_DEFAULT_OFF,
    VCOMP_DEFAULT_ON,
};

#define VCOMP_DEFAULT_MIN   VCOMP_DEFAULT_OFF
#define VCOMP_DEFAULT_MAX   VCOMP_DEFAULT_ON
#define VCOMP_DEFAULT_COUNT (VCOMP_DEFAULT_MAX + 1)

enum vcomp_algorithm {
    VCOMP_ALGO_LZ4,
};

#define VCOMP_ALGO_MIN   VCOMP_ALGO_LZ4
#define VCOMP_ALGO_MAX   VCOMP_ALGO_LZ4
#define VCOMP_ALGO_COUNT (VCOMP_ALGO_MAX + 1)

extern const struct compress_ops *vcomp_compress_ops[VCOMP_ALGO_COUNT];

#endif
