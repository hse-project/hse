/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_PLATFORM_ALLOC_H
#define HSE_PLATFORM_ALLOC_H

#include <hse/util/base.h>
#include <hse/util/page.h>

/* MTF_MOCK_DECL(alloc) */

#if HSE_MOCKING
#include <hse/test/mock/allocation.h>
#include "alloc_ut.h"
#endif /* HSE_MOCKING */

#endif
