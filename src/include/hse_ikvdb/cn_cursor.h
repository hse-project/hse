/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVS_CN_CURSOR_H
#define HSE_IKVS_CN_CURSOR_H

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>

#pragma GCC visibility push(hidden)

/* MTF_MOCK_DECL(cn_cursor) */

struct cn;
struct kvs_ktuple;
struct kvs_kvtuple;
struct cursor_summary;

/* MTF_MOCK */
merr_t
cn_cursor_create(
    struct cn *            cn,
    u64                    seqno,
    bool                   reverse,
    const void *           prefix,
    u32                    len,
    struct cursor_summary *summary,
    void **                cursorp);

/* MTF_MOCK */
merr_t
cn_cursor_update(void *cursor, u64 seqno, bool *updated);

/* MTF_MOCK */
merr_t
cn_cursor_seek(
    void *             cursor,
    const void *       prefix,
    u32                len,
    struct kc_filter * filter,
    struct kvs_ktuple *kt);

/* MTF_MOCK */
merr_t
cn_cursor_read(void *cursor, struct kvs_kvtuple *kvt, bool *eof);

/* MTF_MOCK */
void
cn_cursor_destroy(void *cursor);

/* MTF_MOCK */
merr_t
cn_cursor_active_kvsets(void *cursor, u32 *active, u32 *total);

#pragma GCC visibility pop

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "cn_cursor_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
