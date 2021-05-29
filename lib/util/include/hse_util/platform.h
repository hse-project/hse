/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_PLATFORM_H
#define HSE_PLATFORM_PLATFORM_H

#include <hse_util/base.h>
#include <hse_util/arch.h>
#include <hse_util/hse_err.h>

extern merr_t hse_platform_init(void);
extern void hse_platform_fini(void);

#endif /* HSE_PLATFORM_PLATFORM_H */
