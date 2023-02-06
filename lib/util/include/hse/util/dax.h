/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#ifndef HSE_PLATFORM_DAX_H
#define HSE_PLATFORM_DAX_H

#include <hse/util/base.h>
#include <hse/error/merr.h>

/* MTF_MOCK_DECL(dax) */

/**
 * dax_path_is_fsdax() - check if the given path is on a DAX filesystem
 * @path:  input path
 * @isdax: true, if the specified path is on a DAX FS; false, otherwise
 */
/* MTF_MOCK */
merr_t
dax_path_is_fsdax(const char *path, bool *isdax);

#if HSE_MOCKING
#include "dax_ut.h"
#endif /* HSE_MOCKING */

#endif /* HSE_PLATFORM_DAX_H */
