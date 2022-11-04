/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_REST_PRIVATE_STATUS_H
#define HSE_REST_PRIVATE_STATUS_H

#include <hse/rest/status.h>
#include <hse/util/compiler.h>

const char *
status_to_reason(enum rest_status status) HSE_RETURNS_NONNULL;

#endif
