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
#include <hse_ikvdb/home.h>
#include <pidfile/pidfile.h>

merr_t
kvdb_home_translate(const char *home, char *buf, const size_t buf_sz)
{
    assert(buf);
    assert(buf_sz > 0);

    if (!home) {
        if (!getcwd(buf, buf_sz))
            return merr(errno);

        return 0;
    }

    if (!realpath(home, buf))
        return merr(errno);

    return 0;
}

static size_t
path_copy(const char *home, const char *path, char *buf, const size_t buf_sz)
{
    assert(home);
    assert(path);
    assert(buf);
    assert(buf_sz > 0);

    if (path[0] == '\0') {
        memset(buf, '\0', buf_sz);
        /* -1 to match what strlcpy() and snprintf() return */
        return buf_sz - 1;
    }

    if (path[0] == '/')
        return strlcpy(buf, path, buf_sz);

    return snprintf(buf, buf_sz, "%s/%s", home, path);
}

size_t
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

size_t
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

size_t
kvdb_home_socket_path_get(const char *home, const char *socket_path, char *buf, const size_t buf_sz)
{
    assert(home);
    assert(socket_path);
    assert(buf);
    assert(buf_sz > 0);

    return path_copy(home, socket_path, buf, buf_sz);
}

size_t
kvdb_home_pidfile_path_get(const char *home, char *buf, const size_t buf_sz)
{
    assert(home);
    assert(buf);
    assert(buf_sz > 0);

    return snprintf(buf, buf_sz, "%s/" PIDFILE_NAME, home);
}
