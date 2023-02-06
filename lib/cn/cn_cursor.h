/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_CN_CURSOR_H
#define HSE_KVDB_CN_CURSOR_H

#include <stdint.h>

#include <hse/error/merr.h>
#include <hse/limits.h>
#include <hse/util/bin_heap.h>
#include <hse/util/table.h>

#include <hse/ikvdb/cursor.h>

#include "cn_metrics.h"
#include "kvset.h"
#include "kv_iterator.h"

/* MTF_MOCK_DECL(cn_cursor) */

struct cn;
struct kvs_ktuple;
struct kvs_kvtuple;
struct cursor_summary;

#define NUM_LEVELS (2)

struct cn_level_cursor {
    struct element_source   cnlc_es;
    struct table           *cnlc_kvref_tab;
    struct bin_heap        *cnlc_bh;
    size_t                  cnlc_bh_max_cnt;
    uint32_t                cnlc_iterc;
    uint                    cnlc_level;
    struct kv_iterator    **cnlc_iterv;
    struct cn_kv_item       cnlc_item;
    struct element_source **cnlc_esrcv;
    size_t                  cnlc_esrcc;
    struct cn_cursor       *cnlc_cncur;
    uint64_t                cnlc_dgen_hi;
    uint64_t                cnlc_dgen_lo;
    bool                    cnlc_islast;

    uint                    cnlc_next_eklen;
    unsigned char           cnlc_next_ekey[HSE_KVS_KEY_LEN_MAX];
};

/**
 * struct cn_cursor - allocated prefix scan context, including output buffer
 * @cncur_es:          element source for the kvs cursor
 * @cncur_cn:          cn this cursor operates upon
 * @cncur_bh:          how to merge iterators
 * @cncur_iterc:       number of kvsets referenced
 * @cncur_iterv:       kvset iterator vector
 * @cncur_esrcv:       element source vector
 * @cncur_summary:
 * @cncur_pfx:         prefix is saved here
 * @cncur_pfxlen:      length of the prefix
 * @cncur_tree_pfxlen: length of the tree prefix
 * @cncur_merr:        if cursor is in error state, this is why
 * @cncur_dgen:        max dgen in this scan
 * @cncur_seqno:       view sequence number for this cursor
 * @cncur_reverse:     reverse iterator: 1=yes 0=no
 * @cncur_eof:         cursor is at eof: 1=yes 0=no
 * @cncur_pt_set:      if the ptomb in cncur_pt_kobj, if there is one, is relevant.
 * @cncur_stats:       metrics for this scan; exists lifetime of cursor
 * @cncur_filter:
 * @cncur_pt_kobj:     ptomb key obj (key in kblk OR pt_buf[] right after cur update)
 * @cncur_pt_seq:      ptomb's seqno
 */
struct cn_cursor {
    struct element_source   cncur_es;
    struct cn *             cncur_cn;

    struct bin_heap *cncur_bh;

    struct cn_level_cursor cncur_lcur[NUM_LEVELS];
    uint32_t               cncur_iterc;

    struct element_source  *cncur_esrcv[NUM_LEVELS];
    struct cursor_summary * cncur_summary;
    const void *            cncur_pfx;
    uint32_t                cncur_pfxlen;
    uint32_t                cncur_tree_pfxlen;
    merr_t                  cncur_merr;
    uint64_t                cncur_dgen;
    uint64_t                cncur_seqno;
    enum kvset_iter_flags   cncur_flags;

    struct kvs_cursor_element cncur_elem;

    /* bitflags */
    uint32_t cncur_reverse : 1;
    uint32_t cncur_eof : 1;
    uint32_t cncur_pt_set : 1;
    uint32_t cncur_pt_level : 1;
    uint32_t cncur_first_read : 1;

    struct cn_merge_stats cncur_stats;
    struct kc_filter *    cncur_filter;

    struct key_obj cncur_pt_kobj;
    uint64_t       cncur_pt_seq;
};

/* MTF_MOCK */
merr_t
cn_cursor_create(
    struct cn *            cn,
    uint64_t               seqno,
    bool                   reverse,
    const void *           prefix,
    uint32_t               len,
    struct cursor_summary *summary,
    struct cn_cursor **    cursorp);

/* MTF_MOCK */
merr_t
cn_cursor_update(struct cn_cursor *cursor, uint64_t seqno, bool *updated);

/* MTF_MOCK */
merr_t
cn_cursor_seek(
    struct cn_cursor * cursor,
    const void *       prefix,
    uint32_t           len,
    struct kc_filter * filter);

/* MTF_MOCK */
merr_t
cn_cursor_read(struct cn_cursor *cursor, struct kvs_cursor_element *elem, bool *eof);

/* MTF_MOCK */
void
cn_cursor_destroy(struct cn_cursor *cursor);

/* MTF_MOCK */
merr_t
cn_cursor_active_kvsets(struct cn_cursor *cursor, uint32_t *active, uint32_t *total);

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
