/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_MMAN_H
#define HSE_PLATFORM_MMAN_H

#include <sys/mman.h>
#include <linux/mman.h>

#ifndef MADV_FREE
#define MADV_FREE MADV_DONTNEED
#endif

#endif
