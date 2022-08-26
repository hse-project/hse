/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_kvdb_meta

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <tgmath.h>
#include <unistd.h>

#include <bsd/string.h>
#include <cjson/cJSON.h>

#include <hse/hse.h>
#include <hse/logging/logging.h>

#include <hse_ikvdb/kvdb_meta.h>
#include <hse_ikvdb/kvdb_home.h>
#include <hse_ikvdb/omf_version.h>
#include <hse_util/assert.h>
#include <hse_util/base.h>

#include <mpool/mpool.h>

#define KVDB_META       "kvdb.meta"
#define KVDB_META_PERMS (S_IRUSR | S_IWUSR)

static merr_t
kvdb_meta_open(const char *const kvdb_home, FILE **meta_file)
{
    char   buf[PATH_MAX];
    int    meta_fd;
    int    n;
    merr_t err = 0;

    assert(kvdb_home);
    assert(meta_file);

    *meta_file = NULL;

    n = snprintf(buf, sizeof(buf), "%s/" KVDB_META, kvdb_home);
    if (n >= sizeof(buf))
        return merr(ENAMETOOLONG);
    if (n < 0)
        return merr(EBADMSG);

    meta_fd = open(buf, O_RDWR | O_SYNC, KVDB_META_PERMS);
    if (meta_fd == -1)
        return merr(errno);

    *meta_file = fdopen(meta_fd, "r+");
    if (!*meta_file)
        return merr(errno);

    return err;
}

merr_t
kvdb_meta_create(const char *const kvdb_home)
{
    char buf[PATH_MAX];
    int  meta_fd;
    int  n;

    assert(kvdb_home);

    n = snprintf(buf, sizeof(buf), "%s/" KVDB_META, kvdb_home);
    if (n >= sizeof(buf))
        return merr(ENAMETOOLONG);
    if (n < 0)
        return merr(EBADMSG);

    meta_fd = open(buf, O_CREAT | O_WRONLY | O_EXCL, KVDB_META_PERMS);
    if (meta_fd == -1)
        return merr(errno);

    if (close(meta_fd) == -1)
        return merr(errno);

    return 0;
}

merr_t
kvdb_meta_destroy(const char *const kvdb_home)
{
    char buf[PATH_MAX];
    int  n;

    assert(kvdb_home);

    n = snprintf(buf, sizeof(buf), "%s/" KVDB_META, kvdb_home);
    if (n >= sizeof(buf))
        return merr(ENAMETOOLONG);
    if (n < 0)
        return merr(EBADMSG);

    if (remove(buf) == -1)
        return merr(errno);

    return 0;
}

merr_t
kvdb_meta_serialize(const struct kvdb_meta *const meta, const char *const kvdb_home)
{
    merr_t err = 0;
    cJSON *root, *wal, *cndb, *storage, *mclass[HSE_MCLASS_COUNT];
    char * str = NULL;
    size_t str_sz;
    size_t written;
    FILE * meta_file = NULL;
    int i;

    assert(kvdb_home);
    assert(meta);

    root = cJSON_CreateObject();
    if (!root) {
        err = merr(ENOMEM);
        goto out;
    }

    if (!cJSON_AddNumberToObject(root, "version", meta->km_version)) {
        err = merr(ENOMEM);
        goto out;
    }
    if (!cJSON_AddNumberToObject(root, "omf_version", meta->km_omf_version)) {
        err = merr(ENOMEM);
        goto out;
    }
    cndb = cJSON_AddObjectToObject(root, "cndb");
    if (!cndb) {
        err = merr(ENOMEM);
        goto out;
    }
    if (!cJSON_AddNumberToObject(cndb, "oid1", meta->km_cndb.oid1)) {
        err = merr(ENOMEM);
        goto out;
    }
    if (!cJSON_AddNumberToObject(cndb, "oid2", meta->km_cndb.oid2)) {
        err = merr(ENOMEM);
        goto out;
    }

    wal = cJSON_AddObjectToObject(root, "wal");
    if (!wal) {
        err = merr(ENOMEM);
        goto out;
    }
    if (!cJSON_AddNumberToObject(wal, "oid1", meta->km_wal.oid1)) {
        err = merr(ENOMEM);
        goto out;
    }
    if (!cJSON_AddNumberToObject(wal, "oid2", meta->km_wal.oid2)) {
        err = merr(ENOMEM);
        goto out;
    }

    storage = cJSON_AddObjectToObject(root, "storage");
    if (!storage) {
        err = merr(ENOMEM);
        goto out;
    }

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        mclass[i] = cJSON_AddObjectToObject(storage, hse_mclass_name_get(i));
        if (!mclass[i]) {
            err = merr(ENOMEM);
            goto out;
        }

        if (meta->km_storage[i].path[0] != '\0') {
            if (!cJSON_AddStringToObject(mclass[i], "path", meta->km_storage[i].path)) {
                err = merr(ENOMEM);
                goto out;
            }
        } else {
            if (!cJSON_AddNullToObject(mclass[i], "path")) {
                err = merr(ENOMEM);
                goto out;
            }
        }
    }

    str = cJSON_Print(root);
    if (!str) {
        err = merr(ENOMEM);
        goto out;
    }
    str_sz = strlen(str);

    err = kvdb_meta_open(kvdb_home, &meta_file);
    if (err)
        goto out;

    written = fwrite(str, str_sz, 1, meta_file);
    if (written != 1) {
        err = merr(errno);
        goto out;
    }

out:
    if (meta_file && fclose(meta_file) == EOF && !err)
        err = merr(errno);
    cJSON_Delete(root);
    if (str)
        free(str);

    return err;
}

static bool
check_keys(const cJSON *const node, const size_t keys_sz, const char *const *const keys)
{
    assert(node);
    assert(keys);

    for (const cJSON *n = node->child; n; n = n->next) {
        bool found = false;
        for (size_t i = 0; i < keys_sz; i++) {
            if (!strcmp(n->string, keys[i])) {
                found = true;
                break;
            }
        }

        if (!found)
            return false;
    }

    return true;
}

static bool
check_root_keys(const cJSON *const root)
{
    static const char *keys[] = { "cndb", "wal", "storage", "version", "omf_version" };

    assert(root);

    return check_keys(root, NELEM(keys), keys);
}

static bool
check_cndb_keys(const cJSON *const node)
{
    static const char *keys[] = { "oid1", "oid2" };

    assert(node);

    return check_keys(node, NELEM(keys), keys);
}

static bool
check_wal_keys(const cJSON *const node)
{
    static const char *keys[] = { "oid1", "oid2" };

    assert(node);

    return check_keys(node, NELEM(keys), keys);
}

static bool
check_storage_keys(const cJSON *const node)
{
    assert(node);

    for (const cJSON *n = node->child; n; n = n->next) {
        bool found = false;
        for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
            if (!strcmp(n->string, hse_mclass_name_get(i))) {
                found = true;
                break;
            }
        }

        if (!found)
            return false;
    }

    return true;
}

static bool
check_media_class_keys(const cJSON *const node)
{
    static const char *keys[] = { "path" };

    assert(node);

    return check_keys(node, NELEM(keys), keys);
}

static merr_t
parse_v1(const cJSON *const root, struct kvdb_meta *const meta, const char *const kvdb_home)
{
    size_t n;
    double omf_version_val, cndb_oid1_val, cndb_oid2_val, wal_oid1_val, wal_oid2_val;
    cJSON *omf_version, *wal, *wal_oid1, *wal_oid2, *cndb, *cndb_oid1, *cndb_oid2, *storage;
    cJSON *mclass[HSE_MCLASS_COUNT], *mclass_path[HSE_MCLASS_COUNT];
    int i;

    INVARIANT(root);
    INVARIANT(meta);

    omf_version = cJSON_GetObjectItemCaseSensitive(root, "omf_version");
    if (!cJSON_IsNumber(omf_version))
        return merr(EPROTO);

    cndb = cJSON_GetObjectItemCaseSensitive(root, "cndb");
    if (!cJSON_IsObject(cndb) || !check_cndb_keys(cndb))
        return merr(EPROTO);

    wal = cJSON_GetObjectItemCaseSensitive(root, "wal");
    if (!cJSON_IsObject(wal) || !check_wal_keys(wal))
        return merr(EPROTO);

    storage = cJSON_GetObjectItemCaseSensitive(root, "storage");
    if (!cJSON_IsObject(storage) || !check_storage_keys(storage))
        return merr(EPROTO);

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        if (i != HSE_MCLASS_PMEM) {
            mclass[i] = cJSON_GetObjectItemCaseSensitive(storage, hse_mclass_name_get(i));
            if (!cJSON_IsObject(mclass[i]) || !check_media_class_keys(mclass[i]))
                return merr(EPROTO);
        }
    }

    cndb_oid1 = cJSON_GetObjectItemCaseSensitive(cndb, "oid1");
    cndb_oid2 = cJSON_GetObjectItemCaseSensitive(cndb, "oid2");
    if (!cJSON_IsNumber(cndb_oid1) || !cJSON_IsNumber(cndb_oid2))
        return merr(EPROTO);

    wal_oid1 = cJSON_GetObjectItemCaseSensitive(wal, "oid1");
    wal_oid2 = cJSON_GetObjectItemCaseSensitive(wal, "oid2");
    if (!cJSON_IsNumber(wal_oid1) || !cJSON_IsNumber(wal_oid2))
        return merr(EPROTO);

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        if (i != HSE_MCLASS_PMEM) {
            mclass_path[i] = cJSON_GetObjectItemCaseSensitive(mclass[i], "path");

            if (i == HSE_MCLASS_CAPACITY && !cJSON_IsString(mclass_path[i]))
                return merr(EPROTO);

            if (!(cJSON_IsString(mclass_path[i]) || cJSON_IsNull(mclass_path[i])))
                return merr(EPROTO);
        }
    }

    omf_version_val = cJSON_GetNumberValue(omf_version);
    if (round(omf_version_val) != omf_version_val || omf_version_val <= 0.0 ||
        omf_version_val > UINT_MAX) {
        log_err("'omf_version' key in %s/kvdb.meta must be a whole number greater than 0 and "
                "less than or equal to %d, found %f",
                kvdb_home, UINT_MAX, omf_version_val);
        return merr(EPROTO);
    }

    cndb_oid1_val = cJSON_GetNumberValue(cndb_oid1);
    if (round(cndb_oid1_val) != cndb_oid1_val || cndb_oid1_val > (double)UINT64_MAX ||
        cndb_oid1_val < 0)
        return merr(EPROTO);

    cndb_oid2_val = cJSON_GetNumberValue(cndb_oid2);
    if (round(cndb_oid2_val) != cndb_oid2_val || cndb_oid2_val > (double)UINT64_MAX ||
        cndb_oid2_val < 0)
        return merr(EPROTO);

    wal_oid1_val = cJSON_GetNumberValue(wal_oid1);
    if (round(wal_oid1_val) != wal_oid1_val || wal_oid1_val > (double)UINT64_MAX ||
        wal_oid1_val < 0)
        return merr(EPROTO);

    wal_oid2_val = cJSON_GetNumberValue(wal_oid2);
    if (round(wal_oid2_val) != wal_oid2_val || wal_oid2_val > (double)UINT64_MAX ||
        wal_oid2_val < 0)
        return merr(EPROTO);

    meta->km_omf_version = omf_version_val;
    meta->km_cndb.oid1 = cndb_oid1_val;
    meta->km_cndb.oid2 = cndb_oid2_val;
    meta->km_wal.oid1 = wal_oid1_val;
    meta->km_wal.oid2 = wal_oid2_val;

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        if (i == HSE_MCLASS_PMEM) {
            memset(meta->km_storage[i].path, 0, sizeof(meta->km_storage[i].path));
        } else {
            if (cJSON_IsNull(mclass_path[i])) {
                assert(i != HSE_MCLASS_CAPACITY);
                memset(meta->km_storage[i].path, 0, sizeof(meta->km_storage[i].path));
            } else {
                n = strlcpy(meta->km_storage[i].path, cJSON_GetStringValue(mclass_path[i]),
                            sizeof(meta->km_storage[i].path));
                if (n >= sizeof(meta->km_storage[i].path))
                    return merr(ENAMETOOLONG);
            }
        }
    }

    return 0;
}

static merr_t
parse_v2(const cJSON *const root, struct kvdb_meta *const meta, const char *const kvdb_home)
{
    size_t n;
    double omf_version_val, cndb_oid1_val, cndb_oid2_val, wal_oid1_val, wal_oid2_val;
    cJSON *omf_version, *wal, *wal_oid1, *wal_oid2, *cndb, *cndb_oid1, *cndb_oid2, *storage;
    cJSON *mclass[HSE_MCLASS_COUNT], *mclass_path[HSE_MCLASS_COUNT];
    int i;

    INVARIANT(root);
    INVARIANT(meta);

    omf_version = cJSON_GetObjectItemCaseSensitive(root, "omf_version");
    if (!cJSON_IsNumber(omf_version))
        return merr(EPROTO);

    cndb = cJSON_GetObjectItemCaseSensitive(root, "cndb");
    if (!cJSON_IsObject(cndb) || !check_cndb_keys(cndb))
        return merr(EPROTO);

    wal = cJSON_GetObjectItemCaseSensitive(root, "wal");
    if (!cJSON_IsObject(wal) || !check_wal_keys(wal))
        return merr(EPROTO);

    storage = cJSON_GetObjectItemCaseSensitive(root, "storage");
    if (!cJSON_IsObject(storage) || !check_storage_keys(storage))
        return merr(EPROTO);

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        mclass[i] = cJSON_GetObjectItemCaseSensitive(storage, hse_mclass_name_get(i));
        if (!cJSON_IsObject(mclass[i]) || !check_media_class_keys(mclass[i]))
            return merr(EPROTO);
    }

    cndb_oid1 = cJSON_GetObjectItemCaseSensitive(cndb, "oid1");
    cndb_oid2 = cJSON_GetObjectItemCaseSensitive(cndb, "oid2");
    if (!cJSON_IsNumber(cndb_oid1) || !cJSON_IsNumber(cndb_oid2))
        return merr(EPROTO);

    wal_oid1 = cJSON_GetObjectItemCaseSensitive(wal, "oid1");
    wal_oid2 = cJSON_GetObjectItemCaseSensitive(wal, "oid2");
    if (!cJSON_IsNumber(wal_oid1) || !cJSON_IsNumber(wal_oid2))
        return merr(EPROTO);

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        mclass_path[i] = cJSON_GetObjectItemCaseSensitive(mclass[i], "path");

        if (!(cJSON_IsString(mclass_path[i]) || cJSON_IsNull(mclass_path[i])))
            return merr(EPROTO);
    }

    omf_version_val = cJSON_GetNumberValue(omf_version);
    if (round(omf_version_val) != omf_version_val || omf_version_val <= 0.0 ||
        omf_version_val > UINT_MAX) {
        log_err("'omf_version' key in %s/kvdb.meta must be a whole number greater than 0 and "
                "less than or equal to %d, found %f",
                kvdb_home, UINT_MAX, omf_version_val);
        return merr(EPROTO);
    }

    cndb_oid1_val = cJSON_GetNumberValue(cndb_oid1);
    if (round(cndb_oid1_val) != cndb_oid1_val || cndb_oid1_val > (double)UINT64_MAX ||
        cndb_oid1_val < 0)
        return merr(EPROTO);

    cndb_oid2_val = cJSON_GetNumberValue(cndb_oid2);
    if (round(cndb_oid2_val) != cndb_oid2_val || cndb_oid2_val > (double)UINT64_MAX ||
        cndb_oid2_val < 0)
        return merr(EPROTO);

    wal_oid1_val = cJSON_GetNumberValue(wal_oid1);
    if (round(wal_oid1_val) != wal_oid1_val || wal_oid1_val > (double)UINT64_MAX ||
        wal_oid1_val < 0)
        return merr(EPROTO);

    wal_oid2_val = cJSON_GetNumberValue(wal_oid2);
    if (round(wal_oid2_val) != wal_oid2_val || wal_oid2_val > (double)UINT64_MAX ||
        wal_oid2_val < 0)
        return merr(EPROTO);

    meta->km_omf_version = omf_version_val;
    meta->km_cndb.oid1 = cndb_oid1_val;
    meta->km_cndb.oid2 = cndb_oid2_val;
    meta->km_wal.oid1 = wal_oid1_val;
    meta->km_wal.oid2 = wal_oid2_val;

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        if (cJSON_IsNull(mclass_path[i])) {
            memset(meta->km_storage[i].path, 0, sizeof(meta->km_storage[i].path));
        } else {
            n = strlcpy(meta->km_storage[i].path, cJSON_GetStringValue(mclass_path[i]),
                        sizeof(meta->km_storage[i].path));
            if (n >= sizeof(meta->km_storage[i].path))
                return merr(ENAMETOOLONG);
        }
    }

    return 0;
}

merr_t
kvdb_meta_deserialize(struct kvdb_meta *const meta, const char *const kvdb_home)
{
    merr_t      err = 0;
    cJSON *     root = NULL, *version;
    char *      meta_data = NULL;
    size_t      n;
    double      version_val;
    FILE *      meta_file;
    int         meta_fd;
    struct stat st;

    assert(kvdb_home);
    assert(meta);

    err = kvdb_meta_open(kvdb_home, &meta_file);
    if (err)
        goto out;

    meta_fd = fileno(meta_file);
    if (meta_fd == -1) {
        err = merr(errno);
        goto out;
    }

    if (fstat(meta_fd, &st) == -1) {
        err = merr(errno);
        goto out;
    }

    meta_data = malloc(st.st_size + 1);
    if (!meta_data) {
        err = merr(ENOMEM);
        goto out;
    }

    n = fread(meta_data, st.st_size, 1, meta_file);
    if (n != 1 || ferror(meta_file)) {
        err = merr(EIO);
        goto out;
    }

    meta_data[st.st_size] = '\0';

    root = cJSON_ParseWithLength(meta_data, st.st_size + 1);
    if (!root) {
        if (cJSON_GetErrorPtr()) {
            err = merr(EPROTO);
        } else {
            err = merr(EINVAL);
        }
        goto out;
    }

    if (!cJSON_IsObject(root) || !check_root_keys(root)) {
        err = merr(EPROTO);
        goto out;
    }

    version = cJSON_GetObjectItemCaseSensitive(root, "version");
    if (!cJSON_IsNumber(version)) {
        log_err("'version' key in %s/kvdb.meta is not a number", kvdb_home);
        err = merr(EPROTO);
        goto out;
    }
    version_val = cJSON_GetNumberValue(version);
    if (round(version_val) != version_val) {
        log_err("'version' key in %s/kvdb.meta is not a whole number", kvdb_home);
        err = merr(EPROTO);
        goto out;
    }
    meta->km_version = (unsigned int)version_val;

    switch (meta->km_version) {
    case KVDB_META_VERSION1:
        err = parse_v1(root, meta, kvdb_home);
        break;
    case KVDB_META_VERSION2:
        err = parse_v2(root, meta, kvdb_home);
        break;
    default:
        log_err("Unknown 'version' in %s/kvdb.meta, %u != %u", kvdb_home, meta->km_version,
                KVDB_META_VERSION);
        err = merr(EPROTO);
        goto out;
    }

    if (!err && meta->km_omf_version > GLOBAL_OMF_VERSION) {
        log_err("Unknown 'omf_version' in %s/kvdb.meta, %u != %u, please upgrade HSE",
                kvdb_home, meta->km_omf_version, GLOBAL_OMF_VERSION);
        err = merr(EPROTO);
        goto out;
    }

out:
    if (meta_file && fclose(meta_file) == EOF && !err)
        err = merr(errno);
    cJSON_Delete(root);
    if (meta_data)
        free(meta_data);

    return err;
}

merr_t
kvdb_meta_upgrade(struct kvdb_meta *const meta, const char *const kvdb_home)
{
    unsigned int omvers;
    merr_t err;

    INVARIANT(meta);
    INVARIANT(kvdb_home);

    if (meta->km_version == KVDB_META_VERSION && meta->km_omf_version == GLOBAL_OMF_VERSION)
        return 0; /* Nothing to do */

    omvers = meta->km_omf_version;
    meta->km_omf_version = GLOBAL_OMF_VERSION;
    meta->km_version = KVDB_META_VERSION;

    err = kvdb_meta_serialize(meta, kvdb_home);
    if (err) {
        log_err("Failed to upgrade KVDB global on-media version from %u to %u",
                omvers, meta->km_omf_version);
        return merr(EPROTO);
    }

    log_info("Successfully upgraded KVDB global on-media version from %u to %u",
             omvers, meta->km_omf_version);

    return 0;
}

static_assert(
    sizeof(((struct kvdb_meta *)0)->km_storage[HSE_MCLASS_BASE].path) ==
        sizeof(((struct mpool_cparams *)0)->mclass[HSE_MCLASS_BASE].path),
    "sizes of buffers differ");

static_assert(
    sizeof(((struct kvdb_meta *)0)->km_storage[HSE_MCLASS_BASE].path) ==
        sizeof(((struct mpool_rparams *)0)->mclass[HSE_MCLASS_BASE].path),
    "sizes of buffers differ");

static_assert(
    sizeof(((struct kvdb_meta *)0)->km_storage[HSE_MCLASS_BASE].path) ==
        sizeof(((struct mpool_dparams *)0)->mclass[HSE_MCLASS_BASE].path),
    "sizes of buffers differ");

void
kvdb_meta_from_mpool_cparams(
    struct kvdb_meta *const           meta,
    const char *const                 kvdb_home,
    const struct mpool_cparams *const params)
{
    assert(meta);
    assert(kvdb_home);
    assert(params);

    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        const char *mc_path = params->mclass[i].path;

        /* strnlen() + 1 should move us past the final trailing / */
        strlcpy(meta->km_storage[i].path,
                (mc_path[0] != '/' && strstr(mc_path, kvdb_home)) ?
                mc_path + strnlen(kvdb_home, PATH_MAX) + 1 : mc_path,
                sizeof(meta->km_storage[i].path));
    }
}

merr_t
kvdb_meta_to_mpool_rparams(
    const struct kvdb_meta *const meta,
    const char *const             kvdb_home,
    struct mpool_rparams *const   params)
{
    assert(meta);
    assert(kvdb_home);
    assert(params);

    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        merr_t err;

        err = kvdb_home_storage_path_get(kvdb_home, meta->km_storage[i].path,
                                         params->mclass[i].path, sizeof(params->mclass[i].path));
        if (err)
            return err;
    }

    return 0;
}

merr_t
kvdb_meta_to_mpool_dparams(
    const struct kvdb_meta *const meta,
    const char *const             kvdb_home,
    struct mpool_dparams *const   params)
{
    assert(meta);
    assert(kvdb_home);
    assert(params);

    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        merr_t err;

        err = kvdb_home_storage_path_get(kvdb_home, meta->km_storage[i].path,
                                         params->mclass[i].path, sizeof(params->mclass[i].path));
        if (err)
            return err;
    }

    return 0;
}

merr_t
kvdb_meta_storage_add(
    struct kvdb_meta *          meta,
    const char *                kvdb_home,
    const struct mpool_cparams *cparams)
{
    bool added = false;
    int i;

    assert(meta);
    assert(kvdb_home);
    assert(cparams);

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        const char *path = cparams->mclass[i].path;

        if (path[0] != '\0') {
            assert(meta->km_storage[i].path[0] == '\0');

            strlcpy(meta->km_storage[i].path,
                    (path[0] != '/' && strstr(path, kvdb_home)) ?
                    path + strnlen(kvdb_home, PATH_MAX) + 1 : path,
                    sizeof(meta->km_storage[i].path));
            added = true;
        }
    }

    return added ? kvdb_meta_serialize(meta, kvdb_home) : 0;
}

#if HSE_MOCKING
#include "kvdb_meta_ut_impl.i"
#endif /* HSE_MOCKING */
