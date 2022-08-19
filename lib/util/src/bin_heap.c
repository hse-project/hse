/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_bin_heap

#include <hse_util/arch.h>
#include <hse_util/assert.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/minmax.h>
#include <hse_util/event_counter.h>
#include <hse_util/bin_heap.h>
#include <logging/logging.h>

#define BH_PARENT(_index)   (((_index) - 1) / 2)
#define BH_LEFT(_index)     ((2 * (_index)) + 1)
#define BH_RIGHT(_index)    ((2 * (_index)) + 2)

struct bin_heap {
    void                   *bh_items;
    s32                     bh_item_size;
    s32                     bh_n_items;
    s32                     bh_max_items;
    bin_heap_compare_fn    *bh_compare;
    void                   *bh_item_ptrs[];
};

merr_t
bin_heap_create(
    struct bin_heap **   bh_out,
    size_t               max_items,
    size_t               item_size,
    bin_heap_compare_fn *compare)
{
    struct bin_heap *bh;
    int              i;
    size_t           sz;

    if (ev(!bh_out || !compare || item_size <= 0 || !max_items ))
        return merr(EINVAL);

    sz = sizeof(*bh);
    sz += max_items * sizeof(bh->bh_item_ptrs[0]);
    sz += max_items * item_size;

    bh = malloc(sz);
    if (ev(!bh))
        return merr(ENOMEM);

    memset(bh, 0, sizeof(*bh));
    bh->bh_items = bh->bh_item_ptrs + max_items;
    bh->bh_item_size = item_size;
    bh->bh_n_items = 0;
    bh->bh_max_items = max_items;
    bh->bh_compare = compare;

    for (i = 0; i < max_items; i++)
        bh->bh_item_ptrs[i] = bh->bh_items + i * bh->bh_item_size;

    *bh_out = bh;
    return 0;
}

void
bin_heap_destroy(struct bin_heap *bh)
{
    free(bh);
}

static HSE_ALWAYS_INLINE int
compare_items(struct bin_heap *bh, s32 index1, s32 index2)
{
    return bh->bh_compare(bh->bh_item_ptrs[index1], bh->bh_item_ptrs[index2]);
}

static HSE_ALWAYS_INLINE void
swap_items(struct bin_heap *bh, s32 a_index, s32 b_index)
{
    void *tmp;

    tmp = bh->bh_item_ptrs[a_index];
    bh->bh_item_ptrs[a_index] = bh->bh_item_ptrs[b_index];
    bh->bh_item_ptrs[b_index] = tmp;
}

#if HSE_MOCKING
void
bin_heap_print(struct bin_heap *bh, bool verbose, void (*printer)(const void *))
{
    s32 node;

    assert(bh);
    assert(bh->bh_n_items >= 0);
    assert(bh->bh_n_items <= bh->bh_max_items);
    assert(bh->bh_max_items == 0 || bh->bh_items != NULL);
    assert(bh->bh_compare != NULL);

    if (verbose) {
        log_info("%d items, %d allocated, size %d",
                 bh->bh_n_items,
                 bh->bh_max_items,
                 bh->bh_item_size);
    }

    for (node = 0; node < bh->bh_n_items; node++) {

        s32 size = bh->bh_n_items;
        s32 left = BH_LEFT(node);
        s32 right = BH_RIGHT(node);

        if (verbose) {
            log_info("node[%3d] : Parent %3d, Left %3d, Right %3d :",
                     node,
                     node > 0 ? BH_PARENT(node) : 0,
                     BH_LEFT(node),
                     BH_RIGHT(node));
        }

        if (printer)
            (*printer)(bh->bh_item_ptrs[node]);

        if (left < size) {
            /* expect: node <= left */
            assert(compare_items(bh, node, left) <= 0);
        }

        if (right < size) {
            /* expect: node <= right */
            assert(compare_items(bh, node, right) <= 0);
        }
    }
}

void
bin_heap_check(struct bin_heap *bh)
{
    bin_heap_print(bh, false, NULL);
}
#endif

void
bin_heap_delete_top(struct bin_heap *bh)
{
    s32 node = 0;

    bh->bh_n_items--;
    if (bh->bh_n_items == 0)
        return;

    /* Swap being deleted (index 0) with last item which is empty,
     * keeping in mind that bh_n_items was already decremented */
    swap_items(bh, 0, bh->bh_n_items);

    while (node < bh->bh_n_items) {

        /* find smallest of node, left and right */
        s32 left = BH_LEFT(node);
        s32 right = BH_RIGHT(node);
        s32 smallest = node;

        if (left < bh->bh_n_items && compare_items(bh, left, smallest) < 0)
            smallest = left;

        if (right < bh->bh_n_items && compare_items(bh, right, smallest) < 0)
            smallest = right;

        /* if node is smaller than both children, then we are done. */
        if (smallest == node)
            break;

        /* swap node and smallest */
        swap_items(bh, node, smallest);

        /* repeat at new lower level */
        node = smallest;
    }
}

/* returns false if heap is empty */
bool
bin_heap_get(struct bin_heap *bh, void *item)
{
    if (bh->bh_n_items > 0) {
        /* copy entry 0 into callers item */
        memcpy(item, bh->bh_item_ptrs[0], bh->bh_item_size);
        return true;
    }
    return false;
}

/*
 * Returns false if heap is empty before calling (ie, does not indicate
 * state after deletion)
 */
bool
bin_heap_get_delete(struct bin_heap *bh, void *item)

{
    if (bin_heap_get(bh, item)) {
        bin_heap_delete_top(bh);
        return true;
    }
    return false;
}

merr_t
bin_heap_insert(struct bin_heap *bh, const void *new_item)
{
    s32 curr;

    assert(bh->bh_n_items < bh->bh_max_items);

    /* start with right-most node in last level, which
     * is currently unpopulated */
    curr = bh->bh_n_items;

    /* copy new_item into 'curr' entry */
    memcpy(bh->bh_item_ptrs[curr], new_item, bh->bh_item_size);

    /* account for new node */
    bh->bh_n_items += 1;

    /* walk up the tree from curr */
    while (curr > 0) {
        s32 parent = BH_PARENT(curr);
        int rc = bh->bh_compare(bh->bh_item_ptrs[parent], new_item);

        if (rc < 0) {
            /* parent < new_item: new_item goes into curr */
            break;
        }
        /* parent >= new_item: swap parent and new item */
        swap_items(bh, curr, parent);
        curr = parent;
    }

    return 0;
}

#define BH2_PARENT(_index)  (((_index) - 1) / 2)
#define BH2_LEFT(_index)    (2 * (_index) + 1)
#define BH2_RIGHT(_index)   (2 * (_index) + 2)

static HSE_ALWAYS_INLINE int
bin_heap2_cmp(bin_heap2_compare_fn *cmp, struct heap_node *elts, int a, int b)
{
    int rc = cmp(elts[a].hn_data, elts[b].hn_data);

    return rc ? rc : elts[a].hn_es->es_sort - elts[b].hn_es->es_sort;
}

static void
bin_heap2_heapify(struct bin_heap2 *heap, int index)
{
    int                   l, r;
    int                   xest; /* biggest or smallest index, per cmp */
    int                   heap_sz = heap->bh2_width;
    bin_heap2_compare_fn *cmp = heap->bh2_cmp;
    struct heap_node *    elts = heap->bh2_elts;

restart:
    l = BH2_LEFT(index);
    r = BH2_RIGHT(index);
    xest = index;

    if (l < heap_sz && bin_heap2_cmp(cmp, elts, l, index) < 0)
        xest = l;

    if (r < heap_sz && bin_heap2_cmp(cmp, elts, r, xest) < 0)
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

u32
bin_heap2_width(struct bin_heap2 *bh)
{
    return bh ? bh->bh2_width : 0;
}

void
bin_heap2_init(u32 max_width, bin_heap2_compare_fn *cmp, struct bin_heap2 *bh)
{
    assert(max_width > 0 && cmp && bh);

    bh->bh2_cmp = cmp;
    bh->bh2_max_width = max_width;
    bh->bh2_width = 0;
}

merr_t
bin_heap2_create(u32 max_width, bin_heap2_compare_fn *cmp, struct bin_heap2 **bh_out)
{
    struct bin_heap2 *bh;
    size_t            sz;

    if (HSE_UNLIKELY(max_width < 1 || !cmp || !bh_out))
        return merr(EINVAL);

    sz = sizeof(*bh) + sizeof(struct heap_node) * max_width;

    bh = alloc_aligned(sz, HSE_ACP_LINESIZE);
    if (!bh)
        return merr(ENOMEM);

    bin_heap2_init(max_width, cmp, bh);

    *bh_out = bh;

    return 0;
}

void
bin_heap2_destroy(struct bin_heap2 *bh)
{
    free_aligned(bh);
}

merr_t
bin_heap2_reset(struct bin_heap2 *bh)
{
    bh->bh2_width = 0;
    return 0;
}

merr_t
bin_heap2_prepare(struct bin_heap2 *bh, u32 width, struct element_source *es[])
{
    int i, j;

    if (ev(width > bh->bh2_max_width))
        return merr(EOVERFLOW);

    for (i = 0, j = 0; i < width; ++i) {
        void *elt;

        if (es[i] && es[i]->es_get_next(es[i], &elt)) {
            bh->bh2_elts[j].hn_data = elt;
            bh->bh2_elts[j].hn_es = es[i];
            bh->bh2_elts[j].hn_es->es_sort = j;
            ++j;
        }
    }

    bh->bh2_width = j;
    if (j > 1) {
        for (i = bh->bh2_width / 2 - 1; i >= 0; --i)
            bin_heap2_heapify(bh, i);
    }

    return 0;
}

merr_t
bin_heap2_prepare_list(struct bin_heap2 *bh, u32 width, struct element_source *es)
{
    int i, j;

    for (i = 0, j = 0; es; ++i) {
        void *elt;

        if (j > bh->bh2_max_width)
            return merr(ev(EOVERFLOW));

        if (es->es_get_next(es, &elt)) {
            bh->bh2_elts[j].hn_data = elt;
            bh->bh2_elts[j].hn_es = es;
            bh->bh2_elts[j].hn_es->es_sort = j;
            ++j;
        }
        es = es->es_next_src;
    }

    bh->bh2_width = j;
    if (j > 1) {
        for (i = bh->bh2_width / 2 - 1; i >= 0; --i)
            bin_heap2_heapify(bh, i);
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
s64
bin_heap2_age_cmp(struct element_source *es1, struct element_source *es2)
{
    return es1->es_sort - es2->es_sort;
}

void
bin_heap2_remove_src(struct bin_heap2 *bh, struct element_source *es, bool unget)
{
    int i;

    for (i = 0; i < bh->bh2_width; ++i) {
        if (bh->bh2_elts[i].hn_es == es)
            break;
    }

    if (i >= bh->bh2_width)
        return;

    /* If the last element is replaced with itself, heapify isn't necessary.
     * In fact, heapifying such a bin heap will cause this deleted element
     * to be dereferenced which could be pointing into freed memory.
     *
     * This situation can arise when a cursor is trying to unbind from a
     * transaction that was committed via a flush and the flushed KVMS has
     * been ingested.
     */
    if (i != bh->bh2_width - 1) {
        int j;

        bh->bh2_elts[i] = bh->bh2_elts[bh->bh2_width - 1];
        for (j = bh->bh2_width / 2 - 1; j >= 0; --j)
            bin_heap2_heapify(bh, j);
    }

    --bh->bh2_width;
    if (unget)
        es->es_unget(es);
}

/*
 * bin_heap2_remove_all - remove all active sources from bin_heap
 *
 * When a source is removed from a bin_heap, it has already contributed
 * its next result via es_get_next() (from either prepare or maybe pop).
 * Only the sources still active in the bin_heap must be restored,
 * since sources at eof have nothing within the bin_heap.
 */
void
bin_heap2_remove_all(struct bin_heap2 *bh)
{
    int i;

    for (i = 0; i < bh->bh2_width; ++i) {
        struct element_source *es;

        es = bh->bh2_elts[i].hn_es;
        es->es_unget(es);
    }
    bh->bh2_width = 0;
}

/*
 * bin_heap2_insert_src - insert src as new first sort
 *
 * NB: the new src must be properly positioned before insertion!
 * This is the responsibility of the caller.
 */

merr_t
bin_heap2_insert_src(struct bin_heap2 *bh, struct element_source *es)
{
    struct heap_node *node;
    void *            elt;
    int               width;

    /*
     * ensure the incoming src will fit and has something to contribute;
     * otherwise, we would insert it, then remove it next pop
     */

    width = bh->bh2_width;
    if (width + 1 > bh->bh2_max_width)
        return merr(ev(EOVERFLOW));

    if (!es->es_get_next(es, &elt))
        return 0;

    /*
     * renumber everything, and append new thing
     */
    node = &bh->bh2_elts[0];
    for (int i = 0; i < width; ++i) {
        node->hn_es->es_sort++;
        ++node;
    }

    node->hn_data = elt;
    node->hn_es = es;
    node->hn_es->es_sort = 0;
    ++bh->bh2_width;

    for (int i = bh->bh2_width / 2 - 1; i >= 0; --i)
        bin_heap2_heapify(bh, i);

    return 0;
}

merr_t
bin_heap2_replace_src(struct bin_heap2 *bh, struct element_source *es)
{
    int   i;
    void *es_data;

    if (!es->es_get_next(es, &es_data)) {
        bin_heap2_remove_src(bh, es, true);
        return 0;
    }

    for (i = 0; i < bh->bh2_width; ++i)
        if (bh->bh2_elts[i].hn_es == es)
            break;

    if (i >= bh->bh2_width)
        return merr(ev(ENOENT));

    assert(es->es_sort == bh->bh2_elts[i].hn_es->es_sort);
    bh->bh2_elts[i].hn_data = es_data;

    for (i = bh->bh2_width / 2 - 1; i >= 0; --i)
        bin_heap2_heapify(bh, i);

    return 0;
}

bool
bin_heap2_pop(struct bin_heap2 *bh, void **item)
{
    struct heap_node       node;
    void *                 elt;
    struct element_source *es;
    int                    sort;

    if (bh->bh2_width == 0) {
        if (item)
            *item = NULL;
        return false;
    }

    node = bh->bh2_elts[0];
    es = node.hn_es;
    sort = node.hn_es->es_sort;

    if (es->es_get_next(es, &elt)) {
        bh->bh2_elts[0].hn_data = elt;
        bh->bh2_elts[0].hn_es = es;
        bh->bh2_elts[0].hn_es->es_sort = sort;

    } else if (bh->bh2_width-- > 1) {
        /* an element source was exhausted, narrow the heap  */
        bh->bh2_elts[0] = bh->bh2_elts[bh->bh2_width];
    }

    bin_heap2_heapify(bh, 0);

    if (item)
        *item = node.hn_data;

    return true;
}

bool
bin_heap2_peek(struct bin_heap2 *bh, void **item)
{
    struct heap_node node;

    if (bh->bh2_width == 0) {
        *item = NULL;
        return false;
    }

    node = bh->bh2_elts[0];
    *item = node.hn_data;
    return true;
}

bool
bin_heap2_peek_debug(struct bin_heap2 *bh, void **item, struct element_source **es)
{
    struct heap_node node;

    if (bh->bh2_width == 0) {
        *item = NULL;
        *es = NULL;
        return false;
    }

    node = bh->bh2_elts[0];
    *item = node.hn_data;
    *es = node.hn_es;
    return true;
}

#if HSE_MOCKING
#include "bin_heap_ut_impl.i"
#endif
