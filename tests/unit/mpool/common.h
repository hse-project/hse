/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <dirent.h>
#include <ftw.h>

#include <hse_util/string.h>
#include <hse_util/logging.h>

extern char storage_path[PATH_MAX];
struct mtf_test_info;

int
mpool_test_pre(struct mtf_test_info *info);

int
mpool_test_post(struct mtf_test_info *info);
