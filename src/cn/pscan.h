/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_PSCAN_H
#define HSE_KVDB_CN_PSCAN_H

#include <hse_util/bin_heap.h>
#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>
#include <hse_util/darray.h>
#include "cn_metrics.h"

struct cursor_summary;

/**
 * struct pscan - allocated prefix scan context, including output buffer
 * @stats:      metrics for this scan; exists lifetime of cursor
 * @iterc:      number of kvsets referenced
 * @itermax:    max elements in iterv[] and esrcv[]
 * @iterv:      kvset iterator vector
 * @esrcv:      element source vector
 * @bin_heap:   how to merge iterators
 * @cn:         cn this cursor operates upon
 * @buf:        where to store current key + value
 * @pfx:        prefix is saved here
 * @pfx_len:     length of the prefix
 * @ct_pfx_len:  length of the tree prefix
 * @pfxhash:    hash for this prefix
 * @merr:       if cursor is in error state, this is why
 * @shift:      how to find next child node from pfxhash
 * @mask:
 * @dgen:       max dgen in this scan
 * @eof:        cursor eof separate from iterators
 * @seqno:      view sequence number for this cursor
 * @bufsz:      length of buffer for key + value
 * @reverse:    reverse iterator: 1=yes 0=no
 * @eof:        cursor is at eof: 1=yes 0=no
 * @pt_buf:     buffer for ptomb at cursor update
 * @pt_set:     if the ptomb in pt_kobj, if there is one, is relevant.
 * @pt_kobj:    ptomb key obj (key in kblk OR pt_buf[] right after cur update)
 * @pt_seq:     ptomb's seqno
 */
struct pscan {
    struct bin_heap2 *      bh;
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
    u32                     bufsz;

    /* bitflags */
    u32 reverse : 1;
    u32 eof : 1;
    u32 pt_set : 1;

    struct key_obj pt_kobj;
    u64            pt_seq;
    unsigned char  pt_buf[HSE_KVS_MAX_PFXLEN];

    struct cn_merge_stats stats;
    struct kc_filter *    filter;
    void *                base;

    __aligned(SMP_CACHE_BYTES) char buf[];
};

#endif
