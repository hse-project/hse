/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <bsd/string.h>

#include <hse/util/assert.h>
#include <hse/error/merr.h>
#include <hse/config/config.h>
#include <hse/ikvdb/kvdb_home.h>
#include <hse/ikvdb/kvdb_rparams.h>
#include <hse/ikvdb/kvs_rparams.h>
#include <hse/pidfile/pidfile.h>
#include <hse/util/inttypes.h>
#include <hse/util/dax.h>

static merr_t
path_join(const char *home, const char *path, char *buf, const size_t buf_sz)
{
    int n;

    INVARIANT(home);
    INVARIANT(path);
    INVARIANT(buf);
    INVARIANT(buf_sz > 0);

    if (path[0] == '\0') {
        memset(buf, '\0', buf_sz);
        return 0;
    }

    if (path[0] == '/') {
        if (strlcpy(buf, path, buf_sz) >= buf_sz)
            return merr(ENAMETOOLONG);
        return 0;
    }

    n = snprintf(buf, buf_sz, "%s%s%s", home, home[strlen(home) - 1] == '/' ? "" : "/", path);
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
    int n, rc;
    char namebuf[32];
    const char *dir, *name;

    INVARIANT(home);
    INVARIANT(buf);
    INVARIANT(buf_sz > 0);

    /* If user does not have write access on 'home', then fallback to XDG_RUNTIME_DIR.
     * If XDG_RUNTIME_DIR is not defined or is a relative path, then fallback to /tmp.
     */
    rc = access(home, W_OK);
    if (rc == -1) {
        dir = getenv("XDG_RUNTIME_DIR");
        if (!dir || *dir != '/')
            dir = "/tmp";

        n = snprintf(namebuf, sizeof(namebuf), "hse-%d.pid", getpid());
        assert(n > 0 && n < sizeof(namebuf));

        name = namebuf;
    } else {
        dir = home;
        name = PIDFILE_NAME;
    }

    n = snprintf(buf, buf_sz, "%s%s%s", dir, dir[strlen(dir) - 1] == '/' ? "" : "/", name);
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

merr_t
kvdb_home_check_access(const char *home, enum kvdb_open_mode mode)
{
    int rc;

    if (kvdb_mode_allows_media_writes(mode))
        rc = access(home, R_OK | W_OK | X_OK);
    else
        rc = access(home, R_OK | X_OK);

    return (rc == -1) ? merr(errno) : 0;
}

static merr_t
kvdb_conf_validate(cJSON *const root)
{
    merr_t err;
    cJSON *kvs;
    int num_kvs = 0;
    struct kvdb_rparams kvdb_rp;

    INVARIANT(root);

    err = kvdb_rparams_from_config(&kvdb_rp, root);
    if (err)
        return err;

    kvs = cJSON_GetObjectItemCaseSensitive(root, "kvs");
    if (!kvs)
        return 0;
    if (!cJSON_IsObject(kvs))
        return merr(EINVAL);

    for (cJSON *block = kvs->child; block; block = block->next) {
        struct kvs_rparams kvs_rp;

        if (!cJSON_IsObject(block))
            return merr(EINVAL);

        if (!strcmp(block->string, "default"))
            continue;

        kvs_rp = kvs_rparams_defaults();

        num_kvs++;

        err = kvs_rparams_from_config(&kvs_rp, root, block->string);
        if (err)
            return err;
    }

    if (num_kvs == 0) {
        struct kvs_rparams kvs_rp = kvs_rparams_defaults();

        /* Provide a random KVS name just to validate the default block */
        err = kvs_rparams_from_config(&kvs_rp, root, "dummy");
        if (err)
            return err;
    }

    return err;
}

merr_t
kvdb_home_get_config(const char *home, cJSON **conf)
{
    int n;
    char conf_file_path[PATH_MAX];

    if (!home || !conf)
        return merr(EINVAL);

    n = snprintf(conf_file_path, sizeof(conf_file_path), "%s/kvdb.conf", home);
    if (n >= sizeof(conf_file_path)) {
        return merr(ENAMETOOLONG);
    } else if (n < 0) {
        return merr(EBADMSG);
    }

    return config_open(conf_file_path, kvdb_conf_validate, conf);
}
