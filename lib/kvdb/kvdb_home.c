/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <bsd/string.h>

#include <hse_util/hse_err.h>
#include <hse_ikvdb/kvdb_home.h>
#include <pidfile/pidfile.h>

static merr_t
path_copy(const char *home, const char *path, char *buf, const size_t buf_sz)
{
    assert(home);
    assert(path);
    assert(buf);
    assert(buf_sz > 0);

    int n;

    if (path[0] == '\0') {
        memset(buf, '\0', buf_sz);
        return 0;
    }

    if (path[0] == '/') {
        if (strlcpy(buf, path, buf_sz) >= buf_sz)
            return merr(ENAMETOOLONG);
        return 0;
    }

    n = snprintf(buf, buf_sz, "%s/%s", home, path);
    if (n >= buf_sz)
        return merr(ENAMETOOLONG);
    if (n < 0)
        return merr(EBADMSG);

    return 0;
}

merr_t
kvdb_home_storage_capacity_path_get(
    const char * home,
    const char * capacity_path,
    char *       buf,
    const size_t buf_sz)
{
    assert(home);
    assert(capacity_path);
    assert(buf);
    assert(buf_sz > 0);

    return path_copy(home, capacity_path, buf, buf_sz);
}

merr_t
kvdb_home_storage_staging_path_get(
    const char * home,
    const char * staging_path,
    char *       buf,
    const size_t buf_sz)
{
    assert(home);
    assert(staging_path);
    assert(buf);
    assert(buf_sz > 0);

    return path_copy(home, staging_path, buf, buf_sz);
}

merr_t
kvdb_home_pidfile_path_get(const char *home, char *buf, const size_t buf_sz)
{
    assert(home);
    assert(buf);
    assert(buf_sz > 0);

    int n;

    n = snprintf(buf, buf_sz, "%s/" PIDFILE_NAME, home);
    if (n >= buf_sz)
        return merr(ENAMETOOLONG);
    if (n < 0)
        return merr(EBADMSG);

    return 0;
}
