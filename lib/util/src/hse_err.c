/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/page.h>
#include <hse_util/minmax.h>
#include <hse_util/string.h>
#include <hse_util/hse_err.h>

#include <mpool/mpool.h>

#include <assert.h>
#include <ctype.h>

char hse_merr_bug0[] _merr_attributes = "hse_merr_bug0u";
char hse_merr_bug1[] _merr_attributes = "hse_merr_bug1u";
char hse_merr_bug2[] _merr_attributes = "hse_merr_bug2u";
char hse_merr_bug3[] _merr_attributes = "hse_merr_bug3u";
char hse_merr_base[] _merr_attributes = "hse_merr_baseu";

extern uint8_t __start_hse_merr;
extern uint8_t __stop_hse_merr;

merr_t
merr_pack(int errnum, const char *file, int line)
{
    merr_t err = 0;
    s64    off;

    if (errnum == 0)
        return 0;

    if (errnum < 0)
        errnum = -errnum;

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

    if (((s64)((u64)off << MERR_FILE_SHIFT) >> MERR_FILE_SHIFT) == off)
        err = (u64)off << MERR_FILE_SHIFT;

  finish:
    err |= (1ul << MERR_RSVD_SHIFT);
    err |= ((u64)line << MERR_LINE_SHIFT) & MERR_LINE_MASK;
    err |= errnum & MERR_ERRNO_MASK;

    return err;
}

const char *
merr_file(merr_t err)
{
    const char *file;
    size_t      len;
    int         slash;
    s32         off;

    if (err == 0 || err == -1)
        return NULL;

    off = (s64)(err & MERR_FILE_MASK) >> MERR_FILE_SHIFT;
    if (off == 0)
        return NULL;

    file = hse_merr_base + (off * MERR_ALIGN);

    if (!(file > (char *)&__start_hse_merr ||
          file < (char *)&__stop_hse_merr))
        file = hse_merr_bug3;

    /* [HSE_REVISIT] We can simply 'return file;' here once we teach
     * cmake how to shorten the .c filenames used by _merr_file.
     */
    len = strnlen(file, PATH_MAX);
    file += len;

    for (slash = 0; len-- > 0; --file) {
        if (*file && !isprint(*file))
            return hse_merr_bug2;

        if (file[-1] == '/' && ++slash >= 2)
            break;
    }

    return file;
}

size_t
merr_strerror(merr_t err, char *buf, size_t buf_sz)
{
    char errbuf[1024], *errmsg;
    int errnum = merr_errno(err);

    if (errnum == EBUG)
        return strlcpy(buf, "HSE software bug", buf_sz);

    /* GNU strerror only modifies errbuf if errnum is invalid.
     * It will only return NULL if errbuf is NULL.
     */
    errmsg = strerror_r(errnum, errbuf, sizeof(errbuf));

    return strlcpy(buf, errmsg, buf_sz);
}

char *
merr_strinfo(merr_t err, char *buf, size_t buf_sz, size_t *need_sz)
{
    int off = 0, sz = 0;

    if (err) {
        if (merr_file(err))
            sz = snprintf(buf, buf_sz, "%s:%d: ", merr_file(err), merr_lineno(err));
        if (sz < 0) {
            size_t tmp_sz = strlcpy(buf, "<error formating error message>", buf_sz);

            if (need_sz)
                *need_sz = tmp_sz;

            return buf;
        }

        if (sz >= buf_sz) {
            /* This is the case where even the file and line # didn't fit. We can't safely call
             * merr_strerror() at this point so we tell the caller as much as we can about how
             * much space is likely needed.
             */
            if (need_sz)
                *need_sz = sz + 200;
        }
        else {
            off = sz;
            sz = merr_strerror(err, buf + off, buf_sz - off);

            if (need_sz)
                *need_sz = off + sz;
        }
    } else {
        snprintf(buf, buf_sz, "success");
    }

    return buf;
}
