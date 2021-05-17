/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CURSOR_H
#define HSE_KVDB_CN_CURSOR_H

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>
#include <hse_util/bin_heap.h>
#include <hse_util/darray.h>

#include <hse_ikvdb/cursor.h>

#include "cn_metrics.h"

/* MTF_MOCK_DECL(cn_cursor) */

struct cn;
struct kvs_ktuple;
struct kvs_kvtuple;
struct cursor_summary;

/**
 * struct cn_cursor - allocated prefix scan context, including output buffer
 * @bh:         how to merge iterators
 * @iterc:      number of kvsets referenced
 * @itermax:    max elements in iterv[] and esrcv[]
 * @iterv:      kvset iterator vector
 * @esrcv:      element source vector
 * @cn:         cn this cursor operates upon
 * @summary:
 * @pfx:        prefix is saved here
 * @pfx_len:    length of the prefix
 * @ct_pfx_len: length of the tree prefix
 * @pfxhash:    hash for this prefix
 * @merr:       if cursor is in error state, this is why
 * @shift:      how to find next child node from pfxhash
 * @mask:
 * @dgen:       max dgen in this scan
 * @seqno:      view sequence number for this cursor
 * @reverse:    reverse iterator: 1=yes 0=no
 * @eof:        cursor is at eof: 1=yes 0=no
 * @pt_set:     if the ptomb in pt_kobj, if there is one, is relevant.
 * @stats:      metrics for this scan; exists lifetime of cursor
 * @filter:
 * @pt_kobj:    ptomb key obj (key in kblk OR pt_buf[] right after cur update)
 * @pt_seq:     ptomb's seqno
 * @pt_ptbuf:   buffer for ptomb at cursor update
 * @buf:        where to store current key + value
 */
struct cn_cursor {
    struct bin_heap2 *      bh;
    struct element_source   es;
    struct kvs_cursor_element elem;
    u32                     iterc;
    u32                     itermax;
    struct kv_iterator **   iterv;
    struct element_source **esrcv;
    struct cn *             cn;
    struct cursor_summary * summary;
    const void *            pfx;
    u32                     pfx_len;
    u32                     ct_pfx_len;
    u64                     pfxhash;
    u64                     merr;
    u32                     shift;
    u32                     mask;
    u64                     dgen;
    u64                     seqno;

    /* bitflags */
    u32 reverse : 1;
    u32 eof : 1;
    u32 pt_set : 1;

    struct cn_merge_stats stats;
    struct kc_filter *    filter;

    struct key_obj pt_kobj;
    u64            pt_seq;

    unsigned char  pt_buf[];
};

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
cn_cursor_update(struct cn_cursor *cursor, u64 seqno, bool *updated);

/* MTF_MOCK */
merr_t
cn_cursor_seek(
    struct cn_cursor * cursor,
    const void *       prefix,
    u32                len,
    struct kc_filter * filter);

/* MTF_MOCK */
merr_t
cn_cursor_read(struct cn_cursor *cursor, struct kvs_cursor_element *elem, bool *eof);

/* MTF_MOCK */
void
cn_cursor_destroy(struct cn_cursor *cursor);

/* MTF_MOCK */
merr_t
cn_cursor_active_kvsets(struct cn_cursor *cursor, u32 *active, u32 *total);

/* MTF_MOCK */
struct element_source *
cn_cursor_es_make(struct cn_cursor *cncur);

/* MTF_MOCK */
struct element_source *
cn_cursor_es_get(struct cn_cursor *cncur);

#if HSE_MOCKING
#include "cn_cursor_ut.h"
#endif /* HSE_MOCKING */

#endif
