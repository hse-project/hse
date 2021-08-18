/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_UTIL_INVARIANT_H
#define HSE_UTIL_INVARIANT_H

#include <assert.h>

#ifdef WITH_INVARIANTS
#define INVARIANT(_expr) assert(_expr)
#else
#define INVARIANT(_expr)
#endif

#endif
