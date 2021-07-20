/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>

#include <bsd/string.h>

#include <hse_ikvdb/runtime_home.h>
#include <hse_ikvdb/hse_gparams.h>

char runtime_home[PATH_MAX];

merr_t
runtime_home_set(const char *home)
{
    if (!home) {
        if (!getcwd(runtime_home, sizeof(runtime_home)))
            return merr(errno);
    } else {
        if (!realpath(home, runtime_home))
            return merr(errno);
    }

    return 0;
}

const char *
runtime_home_get(void)
{
    return runtime_home;
}

static merr_t
path_copy(const char *const home, const char *const path, char *const buf, const size_t buf_sz)
{
    assert(path);
    assert(buf);
    assert(buf_sz > 0);

    int n;

    if (path[0] == '\0') {
        memset(buf, 0, buf_sz);
        return 0;
    }

    if (path[0] == '/') {
        if (strlcpy(buf, path, buf_sz) >= buf_sz)
            return merr(ENAMETOOLONG);
        return 0;
    }

    n = snprintf(buf, buf_sz, "%s/%s", home, path);
    if (n < 0)
        return merr(EBADMSG);
    if (n >= buf_sz)
        return merr(ENAMETOOLONG);

    return 0;
}

merr_t
runtime_home_socket_path_get(
    const char *const         home,
    const struct hse_gparams *params,
    char *const               buf,
    const size_t              buf_sz)
{
    assert(home);
    assert(params);
    assert(buf);
    assert(buf_sz > 0);

    if (params->gp_socket.enabled)
        return path_copy(home, params->gp_socket.path, buf, buf_sz);

    memset(buf, 0, buf_sz);
    return 0;
}

merr_t
runtime_home_logging_path_get(
    const char *const         home,
    const struct hse_gparams *params,
    char *const               buf,
    const size_t              buf_sz)
{
    assert(home);
    assert(params);
    assert(buf);
    assert(buf_sz > 0);

    if (params->gp_logging.enabled)
        return path_copy(home, params->gp_logging.path, buf, buf_sz);

    memset(buf, 0, buf_sz);
    return 0;
}
