/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_bin_heap

#include <stdint.h>

#include <hse/logging/logging.h>
#include <hse/util/bin_heap.h>
#include <hse/util/event_counter.h>
#include <hse/util/alloc.h>
#include <hse/util/arch.h>
#include <hse/util/assert.h>
#include <hse/util/minmax.h>
#include <hse/util/slab.h>

#define BH_PARENT(_index)  (((_index) - 1) / 2)
#define BH_LEFT(_index)    (2 * (_index) + 1)
#define BH_RIGHT(_index)   (2 * (_index) + 2)

static HSE_ALWAYS_INLINE int
bin_heap_cmp(bin_heap_compare_fn *cmp, struct heap_node *elts, int a, int b)
{
    const int rc = cmp(elts[a].hn_data, elts[b].hn_data);

    return rc ? rc : elts[a].hn_es->es_sort - elts[b].hn_es->es_sort;
}

static void
bin_heap_heapify(struct bin_heap *heap, int index)
{
    int l, r;
    int xest; /* biggest or smallest index, per cmp */
    int heap_sz = heap->bh_width;
    bin_heap_compare_fn *cmp = heap->bh_cmp;
    struct heap_node *elts = heap->bh_elts;

restart:
    l = BH_LEFT(index);
    r = BH_RIGHT(index);
    xest = index;

    if (l < heap_sz && bin_heap_cmp(cmp, elts, l, index) < 0)
        xest = l;

    if (r < heap_sz && bin_heap_cmp(cmp, elts, r, xest) < 0)
        xest = r;

    if (xest != index) {
        struct heap_node tmp;

        tmp = elts[xest];
        elts[xest] = elts[index];
        elts[index] = tmp;

        index = xest;
        goto restart;
    }
}

uint32_t
bin_heap_width(struct bin_heap *bh)
{
    return bh ? bh->bh_width : 0;
}

void
bin_heap_init(uint32_t max_width, bin_heap_compare_fn *cmp, struct bin_heap *bh)
{
    assert(max_width > 0 && cmp && bh);

    bh->bh_cmp = cmp;
    bh->bh_max_width = max_width;
    bh->bh_width = 0;
}

merr_t
bin_heap_create(uint32_t max_width, bin_heap_compare_fn *cmp, struct bin_heap **bh_out)
{
    size_t sz;
    struct bin_heap *bh;

    if (HSE_UNLIKELY(max_width < 1 || !cmp || !bh_out))
        return merr(EINVAL);

    sz = sizeof(*bh) + sizeof(struct heap_node) * max_width;

    bh = aligned_alloc(HSE_ACP_LINESIZE, ALIGN(sz, HSE_ACP_LINESIZE));
    if (!bh)
        return merr(ENOMEM);

    bin_heap_init(max_width, cmp, bh);

    *bh_out = bh;

    return 0;
}

void
bin_heap_destroy(struct bin_heap *bh)
{
    free(bh);
}

merr_t
bin_heap_reset(struct bin_heap *bh)
{
    bh->bh_width = 0;
    return 0;
}

merr_t
bin_heap_prepare(struct bin_heap *bh, uint32_t width, struct element_source *es[])
{
    int i, j;

    if (ev(width > bh->bh_max_width))
        return merr(EOVERFLOW);

    for (i = 0, j = 0; i < width; ++i) {
        void *elt;

        if (es[i] && es[i]->es_get_next(es[i], &elt)) {
            bh->bh_elts[j].hn_data = elt;
            bh->bh_elts[j].hn_es = es[i];
            bh->bh_elts[j].hn_es->es_sort = j;
            ++j;
        }
    }

    bh->bh_width = j;
    if (j > 1) {
        for (i = bh->bh_width / 2 - 1; i >= 0; --i)
            bin_heap_heapify(bh, i);
    }

    return 0;
}

merr_t
bin_heap_prepare_list(struct bin_heap *bh, uint32_t width, struct element_source *es)
{
    int i, j;

    for (i = 0, j = 0; es; ++i) {
        void *elt;

        if (j > bh->bh_max_width)
            return merr(ev(EOVERFLOW));

        if (es->es_get_next(es, &elt)) {
            bh->bh_elts[j].hn_data = elt;
            bh->bh_elts[j].hn_es = es;
            bh->bh_elts[j].hn_es->es_sort = j;
            ++j;
        }
        es = es->es_next_src;
    }

    bh->bh_width = j;
    if (j > 1) {
        for (i = bh->bh_width / 2 - 1; i >= 0; --i)
            bin_heap_heapify(bh, i);
    }

    return 0;
}

/* Binheap source age comparator.
 *
 * Returns:
 *   < 0 : es1 < es2
 *   > 0 : es1 > es2
 *  == 0 : es1 == es2
 */
int64_t
bin_heap_age_cmp(struct element_source *es1, struct element_source *es2)
{
    return es1->es_sort - es2->es_sort;
}

void
bin_heap_remove_src(struct bin_heap *bh, struct element_source *es, bool unget)
{
    int i;

    for (i = 0; i < bh->bh_width; ++i) {
        if (bh->bh_elts[i].hn_es == es)
            break;
    }

    if (i >= bh->bh_width)
        return;

    /* If the last element is replaced with itself, heapify isn't necessary.
     * In fact, heapifying such a bin heap will cause this deleted element
     * to be dereferenced which could be pointing into freed memory.
     *
     * This situation can arise when a cursor is trying to unbind from a
     * transaction that was committed via a flush and the flushed KVMS has
     * been ingested.
     */
    if (i != bh->bh_width - 1) {
        int j;

        bh->bh_elts[i] = bh->bh_elts[bh->bh_width - 1];
        for (j = bh->bh_width / 2 - 1; j >= 0; --j)
            bin_heap_heapify(bh, j);
    }

    --bh->bh_width;
    if (unget)
        es->es_unget(es);
}

/*
 * bin_heap_remove_all - remove all active sources from bin_heap
 *
 * When a source is removed from a bin_heap, it has already contributed
 * its next result via es_get_next() (from either prepare or maybe pop).
 * Only the sources still active in the bin_heap must be restored,
 * since sources at eof have nothing within the bin_heap.
 */
void
bin_heap_remove_all(struct bin_heap *bh)
{
    int i;

    for (i = 0; i < bh->bh_width; ++i) {
        struct element_source *es;

        es = bh->bh_elts[i].hn_es;
        es->es_unget(es);
    }
    bh->bh_width = 0;
}

/*
 * bin_heap_insert_src - insert src as new first sort
 *
 * NB: the new src must be properly positioned before insertion!
 * This is the responsibility of the caller.
 */

merr_t
bin_heap_insert_src(struct bin_heap *bh, struct element_source *es)
{
    struct heap_node *node;
    void *            elt;
    int               width;

    /*
     * ensure the incoming src will fit and has something to contribute;
     * otherwise, we would insert it, then remove it next pop
     */

    width = bh->bh_width;
    if (width + 1 > bh->bh_max_width)
        return merr(ev(EOVERFLOW));

    if (!es->es_get_next(es, &elt))
        return 0;

    /*
     * renumber everything, and append new thing
     */
    node = &bh->bh_elts[0];
    for (int i = 0; i < width; ++i) {
        node->hn_es->es_sort++;
        ++node;
    }

    node->hn_data = elt;
    node->hn_es = es;
    node->hn_es->es_sort = 0;
    ++bh->bh_width;

    for (int i = bh->bh_width / 2 - 1; i >= 0; --i)
        bin_heap_heapify(bh, i);

    return 0;
}

merr_t
bin_heap_replace_src(struct bin_heap *bh, struct element_source *es)
{
    int   i;
    void *es_data;

    if (!es->es_get_next(es, &es_data)) {
        bin_heap_remove_src(bh, es, true);
        return 0;
    }

    for (i = 0; i < bh->bh_width; ++i)
        if (bh->bh_elts[i].hn_es == es)
            break;

    if (i >= bh->bh_width)
        return merr(ev(ENOENT));

    assert(es->es_sort == bh->bh_elts[i].hn_es->es_sort);
    bh->bh_elts[i].hn_data = es_data;

    for (i = bh->bh_width / 2 - 1; i >= 0; --i)
        bin_heap_heapify(bh, i);

    return 0;
}

bool
bin_heap_pop(struct bin_heap *bh, void **item)
{
    struct heap_node       node;
    void *                 elt;
    struct element_source *es;
    int                    sort;

    if (bh->bh_width == 0) {
        if (item)
            *item = NULL;
        return false;
    }

    node = bh->bh_elts[0];
    es = node.hn_es;
    sort = node.hn_es->es_sort;

    if (es->es_get_next(es, &elt)) {
        bh->bh_elts[0].hn_data = elt;
        bh->bh_elts[0].hn_es = es;
        bh->bh_elts[0].hn_es->es_sort = sort;

    } else if (bh->bh_width-- > 1) {
        /* an element source was exhausted, narrow the heap  */
        bh->bh_elts[0] = bh->bh_elts[bh->bh_width];
    }

    bin_heap_heapify(bh, 0);

    if (item)
        *item = node.hn_data;

    return true;
}

bool
bin_heap_peek(struct bin_heap *bh, void **item)
{
    struct heap_node node;

    if (bh->bh_width == 0) {
        *item = NULL;
        return false;
    }

    node = bh->bh_elts[0];
    *item = node.hn_data;
    return true;
}

bool
bin_heap_peek_debug(struct bin_heap *bh, void **item, struct element_source **es)
{
    struct heap_node node;

    if (bh->bh_width == 0) {
        *item = NULL;
        *es = NULL;
        return false;
    }

    node = bh->bh_elts[0];
    *item = node.hn_data;
    *es = node.hn_es;
    return true;
}

#if HSE_MOCKING
#include "bin_heap_ut_impl.i"
#endif
