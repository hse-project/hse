/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_CGROUP_H
#define HSE_PLATFORM_CGROUP_H

#include <hse_util/base.h>
#include <hse_util/compiler.h>

/**
 * hse_meminfo_cgroup() - Get memory usage for the cgroup if configured
 * @freep:    ptr to return bytes of free memory
 * @availp:   ptr to return bytes of available memory
 * @shift:    shift results by %shift bits
 *
 * %freep and/or %availp may be NULL.
 */
bool
hse_meminfo_cgroup(unsigned long *freep, unsigned long *availp, unsigned int shift);

void
hse_cgroup_fini(void) HSE_COLD;

#endif /* HSE_PLATFORM_CGROUP_H */
