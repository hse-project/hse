/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <stddef.h>

#include <hse/error/merr.h>

merr_t
scratch_directory_setup(const char *ident, char *buf, size_t buf_sz);
