/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/string.h>

#include <hse/hse_version.h>

/**
 * hse_version() - retrieve version string
 * @version:      buffer to receive copy of version string
 * @size:         size of buffer
 *
 * Returns the length of the complete version string.
 *
 * If @size is insufficient, @version contains a truncated result.
 */
size_t
get_hse_version(char *version, size_t size)
{
    return strlcpy(version, hse_version, size);
}
