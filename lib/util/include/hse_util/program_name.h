/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_PROGRAM_NAME_H
#define HSE_PLATFORM_PROGRAM_NAME_H

#include <hse_util/hse_err.h>

/**
 * hse_program_name()
 * @name:           pointer to the name buffer, which the caller will free
 * @base:           pointer to the first character of the basename in @name
 *                  (disinterested callers may pass NULL)
 *
 * retrieves the name of the current executable or module into a new buffer,
 * which the caller must eventually free.
 */
merr_t
hse_program_name(char **name, char **base);

#endif
