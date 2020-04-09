/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_GET_HSE_VERSION_H
#define HSE_GET_HSE_VERSION_H

/**
 * get_hse_version() - retrieve version string
 * @version:      buffer to recieve version string
 * @size:         size of buffer
 *
 * Returns the length of the complete version string.
 *
 * If @size is insufficient, @version contains a truncated result.
 */
size_t
get_hse_version(char *version, size_t size);

#endif
