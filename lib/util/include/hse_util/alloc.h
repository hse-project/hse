/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_ALLOC_H
#define HSE_PLATFORM_ALLOC_H

#include <hse_util/base.h>
#include <hse_util/page.h>

/* MTF_MOCK_DECL(alloc) */

#if HSE_MOCKING
#include <mock/allocation.h>
#include "alloc_ut.h"
#endif /* HSE_MOCKING */

#endif
