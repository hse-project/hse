/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_PLATFORM_ASSERT_H
#define HSE_PLATFORM_ASSERT_H

#include "build_config.h"

#include <assert.h>

#ifdef WITH_INVARIANTS
#define INVARIANT(_expr) assert(_expr)
#else
#define INVARIANT(_expr)
#endif

#endif
