/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include <bsd/string.h>

#include <hse/error/merr.h>
#include <hse_util/assert.h>
#include <hse_util/page.h>

char hse_merr_bug0[] _merr_attributes = "hse_merr_bug0";
char hse_merr_bug1[] _merr_attributes = "hse_merr_bug1";
char hse_merr_bug2[] _merr_attributes = "hse_merr_bug2";
char hse_merr_base[] _merr_attributes = "hse_merr_base";

extern uint8_t __start_hse_merr;
extern uint8_t __stop_hse_merr;

merr_t
merr_pack(const int errno_value, const int16_t ctx, const char *file, const int line)
{
    merr_t  err = 0;
    int64_t off;

    INVARIANT(errno_value >= 0 && errno_value <= INT16_MAX);
    INVARIANT(file);
    INVARIANT(line > 0);

    if (errno_value == 0)
        return 0;

    if (file < (char *)&__start_hse_merr ||
        file >= (char *)&__stop_hse_merr) {
        file = hse_merr_bug0;
    } else if (!IS_ALIGNED((uintptr_t)file, MERR_ALIGN)) {
        file = hse_merr_bug1;
    }

    off = (file - hse_merr_base) / MERR_ALIGN;

    if (((int64_t)((uint64_t)off << MERR_FILE_SHIFT) >> MERR_FILE_SHIFT) == off)
        err = (uint64_t)off << MERR_FILE_SHIFT;

    err |= ((uint64_t)line << MERR_LINE_SHIFT) & MERR_LINE_MASK;
    err |= ((uint64_t)ctx << MERR_CTX_SHIFT) & MERR_CTX_MASK;
    err |= (uint64_t)errno_value & MERR_ERRNO_MASK;

    return err;
}

const char *
merr_file(const merr_t err)
{
    const char *file;
    int32_t     off;

    if (err == 0 || err == -1)
        return NULL;

    off = (int64_t)(err & MERR_FILE_MASK) >> MERR_FILE_SHIFT;
    if (off == 0)
        return NULL;

    file = hse_merr_base + (off * MERR_ALIGN);

    if (file < (char *)&__start_hse_merr ||
          file >= (char *)&__stop_hse_merr)
        return hse_merr_bug2;

#ifdef HSE_REL_SRC_DIR
    if ((uintptr_t)file == (uintptr_t)hse_merr_bug0 ||
        (uintptr_t)file == (uintptr_t)hse_merr_bug1 ||
        (uintptr_t)file == (uintptr_t)hse_merr_bug2) {
        return file;
    }

    /* Point the file pointer past the prefix in order to retrieve the file
     * path relative to the HSE source tree.
     */
    file += sizeof(HSE_REL_SRC_DIR) - 1;
#endif

    return file;
}

size_t
merr_strerror(const merr_t err, char *const buf, const size_t buf_sz)
{
    char errbuf[1024], *errmsg;
    int errno_value = merr_errno(err);

    if (errno_value == EBUG)
        return strlcpy(buf, "HSE software bug", buf_sz);

    /* GNU strerror only modifies errbuf if errno_value is invalid.
     * It will only return NULL if errbuf is NULL.
     */
    errmsg = strerror_r(errno_value, errbuf, sizeof(errbuf));

    return strlcpy(buf, errmsg, buf_sz);
}

char *
merr_strinfo(
    const merr_t err,
    char *const buf,
    const size_t buf_sz,
    merr_stringify ctx_stringify,
    size_t *const need_sz)
{
    int ret = 0;
    size_t sz = 0;
    const char *file = NULL;
    const int16_t ctx = merr_ctx(err);

    if (err) {
        file = merr_file(err);

        if (file) {
            ret = snprintf(buf, buf_sz, "%s:%d: ", file, merr_lineno(err));
            if (ret < 0) {
                sz = strlcpy(buf, "<failed to format error message>", buf_sz);
                goto out;
            }

            sz += (size_t)ret;
        }

        if (sz >= buf_sz) {
            sz += merr_strerror(err, NULL, 0);
        } else {
            sz += merr_strerror(err, buf + sz, buf_sz - sz);
        }

        if (sz >= buf_sz) {
            ret = snprintf(NULL, 0, " (%d)", merr_errno(err));
        } else {
            ret = snprintf(buf + sz, buf_sz - sz, " (%d)", merr_errno(err));
        }

        if (ret < 0) {
            /* Try to just return what we already have. */
            buf[sz] = '\000';
            goto out;
        }

        sz += (size_t)ret;

        if (ctx != 0 && ctx_stringify) {
            const char *msg = ctx_stringify(ctx);

            if (sz >= buf_sz) {
                ret = snprintf(NULL, 0, ": %s (%d)", msg, ctx);
            } else {
                ret = snprintf(buf + sz, buf_sz - sz, ": %s (%d)", msg, ctx);
            }

            if (ret < 0) {
                /* Try to just return what we already have. */
                buf[sz] = '\000';
                goto out;
            }

            sz += (size_t)ret;
        }
    } else {
        sz = strlcpy(buf, "success", buf_sz);
    }

out:
    if (need_sz)
        *need_sz = sz;

    return buf;
}
