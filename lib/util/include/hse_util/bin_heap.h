/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_BIN_HEAP_H
#define HSE_PLATFORM_BIN_HEAP_H

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/element_source.h>

struct bin_heap;

/*
 * The return value of bin_heap_compare_fn determines if the heap
 * structure is a min-heap or a max-heap:
 *  - For min-heaps, it must return a negative value if A is smaller then B.
 *  - For max-heaps, it must return a negative value if A is larger than B.
 */
typedef int
bin_heap_compare_fn(const void *a, const void *b);

merr_t
bin_heap_create(struct bin_heap **bh, u32 max_items, s32 item_size, bin_heap_compare_fn *compare);

void
bin_heap_destroy(struct bin_heap *bh);

void
bin_heap_check(struct bin_heap *bh);

void
bin_heap_print(struct bin_heap *bh, bool verbose, void (*printer)(const void *));

merr_t
bin_heap_preallocate(struct bin_heap *bh, s32 preallocated_items);

merr_t
bin_heap_insert(struct bin_heap *bh, const void *item);

bool
bin_heap_get(struct bin_heap *bh, void *item);

bool
bin_heap_get_delete(struct bin_heap *bh, void *item);

void
bin_heap_delete_top(struct bin_heap *bh);

/* ------------------------------------------------------------------------ */

struct bin_heap2;

/*
 * The return value of bin_heap_compare_fn determines if the heap
 * structure is a min-heap or a max-heap:
 *  - For min-heaps, it must return a negative value if A is smaller then B.
 *  - For max-heaps, it must return a negative value if A is larger than B.
 */
typedef int
bin_heap2_compare_fn(const void *a, const void *b);

struct heap_node {
    void *                 hn_data;
    struct element_source *hn_es;
};

struct bin_heap2 {
    int                   bh2_width;
    int                   bh2_max_width;
    bin_heap2_compare_fn *bh2_cmp;
    struct heap_node      bh2_elts[];
};

u32
bin_heap2_width(struct bin_heap2 *bh);

merr_t
bin_heap2_create(u32 max_width, bin_heap2_compare_fn *cmp, struct bin_heap2 **bh_out);

void
bin_heap2_destroy(struct bin_heap2 *bh);

merr_t
bin_heap2_reset(struct bin_heap2 *bh);

merr_t
bin_heap2_prepare(struct bin_heap2 *bh, u32 width, struct element_source *es[]);

merr_t
bin_heap2_prepare_list(struct bin_heap2 *bh, u32 width, struct element_source *es);

bool
bin_heap2_pop(struct bin_heap2 *bh, void **item);

static HSE_ALWAYS_INLINE bool
bin_heap2_peek(struct bin_heap2 *bh, void **item)
{
    struct heap_node node;

    if (bh->bh2_width == 0) {
        *item = 0;
        return false;
    }

    node = bh->bh2_elts[0];
    *item = node.hn_data;
    return true;
}

bool
bin_heap2_peek_debug(struct bin_heap2 *bh, void **item, struct element_source **es);

/**
 * bin_heap2_remove_src() - Remove source from the bin heap
 * @bh:    handle to the bin heap structure
 * @es:    element source to be removed
 * @unget: whether or not to move the underlying iterators back by one.
 *
 * Since the structures backing the underlying iterators need to exist for
 * unget to succeed, the caller must set the unget flag only if it has a
 * reference on the backing structure.
 */
void
bin_heap2_remove_src(struct bin_heap2 *bh, struct element_source *es, bool unget);

void
bin_heap2_remove_all(struct bin_heap2 *bh);

merr_t
bin_heap2_insert_src(struct bin_heap2 *bh, struct element_source *es);

merr_t
bin_heap2_replace_src(struct bin_heap2 *bh, struct element_source *es);

s64
bin_heap2_age_cmp(struct bin_heap2 *bh, struct element_source *es1, struct element_source *es2);

#endif
