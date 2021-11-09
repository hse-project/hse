/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/page.h>
#include <hse_util/hse_err.h>
#include <hse_util/invariant.h>

#include <assert.h>
#include <ctype.h>
#include <stdint.h>

#include <bsd/string.h>

char hse_merr_bug0[] _merr_attributes = "hse_merr_bug0u";
char hse_merr_bug1[] _merr_attributes = "hse_merr_bug1u";
char hse_merr_bug2[] _merr_attributes = "hse_merr_bug2u";
char hse_merr_bug3[] _merr_attributes = "hse_merr_bug3u";
char hse_merr_base[] _merr_attributes = "hse_merr_baseu";

extern uint8_t __start_hse_merr;
extern uint8_t __stop_hse_merr;

merr_t
merr_pack(int errno_value, const enum hse_err_ctx ctx, const char *file, int line)
{
    merr_t   err = 0;
    uint64_t off;

    INVARIANT(errno_value >= 0 && errno_value <= INT16_MAX);
    INVARIANT(ctx >= 0 && ctx < HSE_ERR_CTX_MAX);
    INVARIANT(file);
    INVARIANT(line > 0);

    if (errno_value == 0)
        return 0;

    if (!file)
        goto finish;

    if (!IS_ALIGNED((ulong)file, sizeof(file)))
        file = hse_merr_bug0; /* invalid file */

    if (!(file > (char *)&__start_hse_merr ||
          file < (char *)&__stop_hse_merr))
        goto finish; /* file outside libhse */

    if (!IS_ALIGNED((ulong)file, MERR_ALIGN))
        file = hse_merr_bug1;

    off = (file - hse_merr_base) / MERR_ALIGN;

    if (((off << MERR_FILE_SHIFT) >> MERR_FILE_SHIFT) == off)
        err = off << MERR_FILE_SHIFT;

  finish:
    err |= ((uint64_t)line << MERR_LINE_SHIFT) & MERR_LINE_MASK;
    err |= (ctx << MERR_CTX_SHIFT) & MERR_CTX_MASK;
    err |= errno_value & MERR_ERRNO_MASK;

    return err;
}

const char *
merr_file(merr_t err)
{
    const char *file;
    uint32_t    off;

    if (err == 0 || err == -1)
        return NULL;

    off = (err & MERR_FILE_MASK) >> MERR_FILE_SHIFT;
    if (off == 0)
        return NULL;

    file = hse_merr_base + (off * MERR_ALIGN);

    if (!(file > (char *)&__start_hse_merr ||
          file < (char *)&__stop_hse_merr))
        return hse_merr_bug3;

#ifdef HSE_REL_SRC_DIR
    if ((uintptr_t)file == (uintptr_t)hse_merr_bug0 ||
        (uintptr_t)file == (uintptr_t)hse_merr_bug1 ||
        (uintptr_t)file == (uintptr_t)hse_merr_bug2 ||
        (uintptr_t)file == (uintptr_t)hse_merr_bug3) {
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
merr_strerror(merr_t err, char *buf, size_t buf_sz)
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
merr_strinfo(merr_t err, char *buf, size_t buf_sz, size_t *need_sz)
{
    ssize_t     sz = 0;
    const char *file = NULL;

    if (err) {
        file = merr_file(err);
        if (file)
            sz = snprintf(buf, buf_sz, "%s:%d: ", file, merr_lineno(err));
        if (sz < 0) {
            sz = strlcpy(buf, "<failed to format error message>", buf_sz);
            goto out;
        }
        if (sz >= buf_sz)
            goto out;

        sz += merr_strerror(err, buf + sz, buf_sz - sz);
    } else {
        sz = strlcpy(buf, "success", buf_sz);
    }

out:
    if (need_sz)
        *need_sz = sz < 0 ? 0 : (size_t)sz;
    return buf;
}
