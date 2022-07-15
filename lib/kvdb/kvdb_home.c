/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <bsd/string.h>

#include <hse_util/assert.h>
#include <error/merr.h>
#include <hse_util/inttypes.h>
#include <hse_util/dax.h>

#include <hse_ikvdb/kvdb_home.h>
#include <pidfile/pidfile.h>

static merr_t
path_join(const char *home, const char *path, char *buf, const size_t buf_sz)
{
    INVARIANT(home);
    INVARIANT(path);
    INVARIANT(buf);
    INVARIANT(buf_sz > 0);

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

    n = snprintf(buf, buf_sz, "%s%s%s", home, home[strlen(home)] == '/' ? "" : "/", path);
    if (n >= buf_sz)
        return merr(ENAMETOOLONG);
    if (n < 0)
        return merr(EBADMSG);

    return 0;
}

merr_t
kvdb_home_storage_path_get(
    const char * home,
    const char * path,
    char *       buf,
    const size_t buf_sz)
{
    INVARIANT(home);
    INVARIANT(path);
    INVARIANT(buf);
    INVARIANT(buf_sz > 0);

    return path_join(home, path, buf, buf_sz);
}

merr_t
kvdb_home_storage_realpath_get(
    const char * home,
    const char * path,
    char         buf[PATH_MAX],
    bool         resolved_path)
{
    merr_t err = 0;

    INVARIANT(home);
    INVARIANT(path);

    if (path[0] == '\0') {
        buf[0] = '\0';
        return 0;
    }

    if (resolved_path) {
        if (strlcpy(buf, path, PATH_MAX) >= PATH_MAX)
            err = merr(ENAMETOOLONG);
    } else {
        err = path_join(home, path, buf, PATH_MAX);
    }

    if (!err) {
        char *pathdup = strndup(buf, PATH_MAX);

        if (!pathdup)
            return merr(ENOMEM);

        if (!realpath(pathdup, buf))
            err = merr(errno);

        free(pathdup);
    }

    return err;
}

merr_t
kvdb_home_pidfile_path_get(const char *home, char *buf, const size_t buf_sz)
{
    INVARIANT(home);
    INVARIANT(buf);
    INVARIANT(buf_sz > 0);

    int n;

    n = snprintf(buf, buf_sz, "%s/" PIDFILE_NAME, home);
    if (n >= buf_sz)
        return merr(ENAMETOOLONG);
    if (n < 0)
        return merr(EBADMSG);

    return 0;
}

merr_t
kvdb_home_is_fsdax(const char *home, bool *isdax)
{
    INVARIANT(home);
    INVARIANT(isdax);

    return dax_path_is_fsdax(home, isdax);
}
