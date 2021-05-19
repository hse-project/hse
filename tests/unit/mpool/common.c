/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/common.h>

#include "common.h"

char storage_path[PATH_MAX];

static int
removecb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    return remove(path);
}

int
mpool_test_pre(struct mtf_test_info *info)
{
    struct mtf_test_coll_info *tcinfo = info->ti_coll;

    char  *pos;
    size_t len, n;
    int    rc;

    if (tcinfo->tci_argc > 1) {
        n = strlcpy(storage_path, tcinfo->tci_argv[1], sizeof(storage_path));
        if (n >= sizeof(storage_path)) {
            hse_log(HSE_ERR "Storage path malformed for test collection %s", tcinfo->tci_coll_name);
            return EINVAL;
        }
    } else {
        hse_log(HSE_ERR "No storage path configured for test collection %s", tcinfo->tci_coll_name);
        return EINVAL;
    }

    len = strlen(storage_path);
    pos = storage_path + len;

    n = snprintf(pos, sizeof(storage_path) - len, "/%s_%s", tcinfo->tci_coll_name, "data");
    if (n >= sizeof(storage_path) - len)
        return EINVAL;

    if (!access(storage_path, F_OK))
        nftw(storage_path, removecb, 32, FTW_PHYS | FTW_DEPTH);

    rc = mkdir(storage_path, S_IRWXU | S_IRWXG | S_IROTH | S_IWOTH);
    if (rc)
        return errno;

    rc = setenv("HSE_STORAGE_PATH", (const char *)storage_path, 1);
    if (rc)
        return errno;

    rc = unsetenv("HSE_STAGING_PATH");
    if (rc)
        return errno;

    return 0;
}

int
mpool_test_post(struct mtf_test_info *info)
{
    int rc;

    nftw(storage_path, removecb, 32, FTW_PHYS | FTW_DEPTH);

    rc = unsetenv("HSE_STORAGE_PATH");
    if (rc)
        return errno;

    rc = unsetenv("HSE_STAGING_PATH");
    if (rc)
        return errno;

    return 0;
}
