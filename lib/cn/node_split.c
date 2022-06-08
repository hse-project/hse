/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <hse_util/element_source.h>
#include <hse_util/event_counter.h>
#include <hse_util/hse_err.h>
#include <hse_util/keycmp.h>

#include "cn_tree_internal.h"
#include "kvset.h"
#include "kvset_internal.h"

struct reverse_kblk_iterator {
    struct kvset *oi_ks;
    struct element_source oi_es;
    bool oi_eof;
    uint32_t oi_offset;
};

static bool
next(struct element_source *source, void **data)
{
    struct reverse_kblk_iterator *iter = container_of(source, struct reverse_kblk_iterator, oi_es);

    if (iter->oi_eof)
        return false;

    assert(iter->oi_offset > 0);

    *data = &iter->oi_ks->ks_kblks[--iter->oi_offset];

    if (iter->oi_offset == 0)
        iter->oi_eof = true;

    return iter->oi_eof;
}

static merr_t
reverse_kblk_iterator_create(
    struct kvset *const ks,
    struct reverse_kblk_iterator **const iter)
{
    struct reverse_kblk_iterator *tmp;

    *iter = NULL;

    tmp = calloc(1, sizeof(*tmp));
    if (ev(!tmp))
        return merr(ENOMEM);

    tmp->oi_ks = ks;
    /* Using prefix decrement in next, so this is fine */
    tmp->oi_offset = ks->ks_st.kst_kblks;
    tmp->oi_es = es_make(next, NULL, NULL);

    *iter = tmp;

    return 0;
}

static void
reverse_kblk_iterator_destroy(struct reverse_kblk_iterator *const iter)
{
    free(iter);
}

static int
kblk_compare(const void *const a, const void *const b)
{
    const struct kvset_kblk *kblk_a = a, *kblk_b = b;

    /* Return the kblock with the largest min key. */
    return -1 * keycmp(kblk_a->kb_koff_min, kblk_a->kb_klen_min, kblk_b->kb_koff_min,
        kblk_b->kb_klen_min);
}

merr_t
cn_tree_node_get_split_key(
    const struct cn_tree_node *const node,
    void *const key_buf,
    const size_t key_buf_sz,
    uint16_t *const key_len)
{
    merr_t err;
    struct bin_heap2 *bh;
    struct kvset_list_entry *le;
    struct kvset_kblk *kblk;
    struct reverse_kblk_iterator **iters = NULL;
    struct element_source **srcs = NULL;
    uint64_t kvset_idx = 0;
    uint64_t wlen = 0;
    const uint64_t num_kvsets = cn_ns_kvsets(&node->tn_ns);
    const uint64_t total_wlen = cn_ns_wlen(&node->tn_ns);

    err = bin_heap2_create(num_kvsets, kblk_compare, &bh);
    if (ev(err))
        return err;

    /* Forgive me for I have sinned; allocate all necessary memory for managing
     * iterators and element sources in one go.
     */
    iters = calloc(1, sizeof(void *) * 2 * num_kvsets);
    if (ev(!iters)) {
        err = merr(ENOMEM);
        goto out;
    }

    srcs = (struct element_source **)(iters + num_kvsets);

    list_for_each_entry(le, &node->tn_kvset_list, le_link) {
        struct reverse_kblk_iterator *iter = *(iters + kvset_idx);

        err = reverse_kblk_iterator_create(le->le_kvset, &iter);
        if (err)
            goto out;

        *(srcs + kvset_idx) = &iter->oi_es;

        kvset_idx++;
    }

    assert(kvset_idx == num_kvsets);

    err = bin_heap2_prepare(bh, num_kvsets, srcs);
    if (ev(err))
        goto out;

    while (bin_heap2_pop(bh, (void **)&kblk)) {
        wlen += kblk->kb_metrics.tot_key_bytes + kblk->kb_metrics.tot_val_bytes;
        if (wlen >= total_wlen / 2)
            break;
    }

    if (key_buf) {
        const size_t copy_len = kblk->kb_klen_min < key_buf_sz ? kblk->kb_klen_min : key_buf_sz;

        memcpy(key_buf, kblk->kb_koff_min, copy_len);
    }
    if (key_len)
        *key_len = kblk->kb_klen_min;

out:
    if (iters) {
        for (uint64_t i = 0; i < num_kvsets; i++)
            reverse_kblk_iterator_destroy(*(iters + i));
    }

    free(iters);
    bin_heap2_destroy(bh);

    return 0;
}
