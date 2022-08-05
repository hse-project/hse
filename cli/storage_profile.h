/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef STORAGE_PROFILE_H
#define STORAGE_PROFILE_H

#include <stdbool.h>

int
hse_storage_profile(const char *path, bool quiet, bool verbose);

#endif /* STORAGE_PROFILE_H */
