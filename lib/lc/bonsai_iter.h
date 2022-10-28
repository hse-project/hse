/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_BONSAI_ITER_H
#define HSE_CORE_BONSAI_ITER_H

#include <hse/error/merr.h>
#include <hse/util/element_source.h>
#include <hse/util/bonsai_tree.h>

#include <hse/ikvdb/cursor.h>

/* MTF_MOCK_DECL(bonsai_iter) */

struct bonsai_iter {
    struct element_source     bi_es;
    struct bonsai_root **     bi_root;
    struct bonsai_kv *        bi_kv;
    struct kvs_cursor_element bi_elem;
    u64                       bi_seq_view;
    u64                       bi_seq_horizon;
    uintptr_t                 bi_seqref;
    int                       bi_index;

    /* Flags */
    u32 bi_reverse : 1;
    u32 bi_is_ptomb : 1;
};

/* MTF_MOCK */
void
bonsai_iter_init(
    struct bonsai_iter * iter,
    struct bonsai_root **root,
    int                  skidx,
    u64                  view_seq,
    u64                  horizon_seq,
    uintptr_t            seqnoref,
    bool                 reverse,
    bool                 ptomb_tree);

/* MTF_MOCK */
void
bonsai_iter_position(struct bonsai_iter *iter, const void *key, size_t klen);

/* MTF_MOCK */
void
bonsai_iter_update(struct bonsai_iter *iter, u64 view_seq, u64 horizon_seq);

/* MTF_MOCK */
void
bonsai_iter_seek(struct bonsai_iter *iter, const void *key, size_t klen);

/* MTF_MOCK */
struct element_source *
bonsai_iter_es_make(struct bonsai_iter *iter);

/* Iterator for ingesting - a simpler iterator than the cursor's */
struct bonsai_ingest_iter {
    struct element_source bii_es;
    struct bonsai_root ** bii_rootp;
    struct bonsai_kv *    bii_kv;
    u64                   bii_min_seqno;
    u64                   bii_max_seqno;
};

struct element_source *
bonsai_ingest_iter_init(
    struct bonsai_ingest_iter *iter,
    u64                        min_seqno,
    u64                        max_seqno,
    struct bonsai_root **      rootp);

#if HSE_MOCKING
#include "bonsai_iter_ut.h"
#endif

#endif /* HSE_CORE_BONSAI_ITER_H */
