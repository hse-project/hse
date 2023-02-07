/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#ifndef HSE_REST_PRIVATE_STATUS_H
#define HSE_REST_PRIVATE_STATUS_H

#include <hse/rest/status.h>
#include <hse/util/compiler.h>

const char *
status_to_reason(enum rest_status status) HSE_RETURNS_NONNULL;

#endif
