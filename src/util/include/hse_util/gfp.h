/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_GFP_H
#define HSE_PLATFORM_GFP_H

/* MTF_MOCK_DECL(gfp) */

#ifndef GFP_KERNEL
#define __GFP_ZERO 0x00000001
#define GFP_ATOMIC 0x00000002
#define GFP_KERNEL 0x00000004
#define GFP_NOWAIT 0x00000008

typedef unsigned gfp_t;
#endif

unsigned long
__get_free_page(gfp_t flags);
unsigned long
get_zeroed_page(gfp_t flags);
void
free_page(unsigned long addr);

/* MTF_MOCK */
unsigned long
mget_free_page(int flags);

#if HSE_UNIT_TEST_MODE
#include "gfp_ut.h"
#endif

#endif /* HSE_PLATFORM_GFP_H */
