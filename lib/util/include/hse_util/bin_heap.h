/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_UTIL_BIN_HEAP_H
#define HSE_UTIL_BIN_HEAP_H

/* MTF_MOCK_DECL(bin_heap) */

#include <hse/error/merr.h>
#include <hse_util/inttypes.h>
#include <hse_util/element_source.h>

/*
 * The return value of bin_heap_compare_fn determines if the heap
 * structure is a min-heap or a max-heap:
 *  - For min-heaps, it must return a negative value if A is smaller then B.
 *  - For max-heaps, it must return a negative value if A is larger than B.
 */
typedef int
bin_heap_compare_fn(const void *a, const void *b);

struct heap_node {
    void *                 hn_data;
    struct element_source *hn_es;
};

#define BIN_HEAP_BODY                      \
    struct {                               \
        int                  bh_width;     \
        int                  bh_max_width; \
        bin_heap_compare_fn *bh_cmp;       \
    }

struct bin_heap {
    BIN_HEAP_BODY;
    struct heap_node bh_elts[];
};

/* This macro defines a fixed-sized bin heap that is compatible
 * with struct bin_heap.  The primary purpose is to eliminate
 * indirection through a pointer to access the elements array.
 */
#define BIN_HEAP_DEFINE(_bh_name, _bh_width)   \
    struct {                                   \
        BIN_HEAP_BODY;                         \
        struct heap_node bh_elts[(_bh_width)]; \
    } _bh_name

u32
bin_heap_width(struct bin_heap *bh);

void
bin_heap_init(u32 max_width, bin_heap_compare_fn *cmp, struct bin_heap *bh);

/* MTF_MOCK */
merr_t
bin_heap_create(u32 max_width, bin_heap_compare_fn *cmp, struct bin_heap **bh_out);

/* MTF_MOCK */
void
bin_heap_destroy(struct bin_heap *bh);

merr_t
bin_heap_reset(struct bin_heap *bh);

/* MTF_MOCK */
merr_t
bin_heap_prepare(struct bin_heap *bh, u32 width, struct element_source *es[]);

merr_t
bin_heap_prepare_list(struct bin_heap *bh, u32 width, struct element_source *es);

/* MTF_MOCK */
bool
bin_heap_pop(struct bin_heap *bh, void **item);

/* MTF_MOCK */
bool
bin_heap_peek(struct bin_heap *bh, void **item);

bool
bin_heap_peek_debug(struct bin_heap *bh, void **item, struct element_source **es);

/**
 * bin_heap_remove_src() - Remove source from the bin heap
 * @bh:    handle to the bin heap structure
 * @es:    element source to be removed
 * @unget: whether or not to move the underlying iterators back by one.
 *
 * Since the structures backing the underlying iterators need to exist for
 * unget to succeed, the caller must set the unget flag only if it has a
 * reference on the backing structure.
 */
void
bin_heap_remove_src(struct bin_heap *bh, struct element_source *es, bool unget);

void
bin_heap_remove_all(struct bin_heap *bh);

merr_t
bin_heap_insert_src(struct bin_heap *bh, struct element_source *es);

merr_t
bin_heap_replace_src(struct bin_heap *bh, struct element_source *es);

s64
bin_heap_age_cmp(struct element_source *es1, struct element_source *es2);

#if HSE_MOCKING
#include "bin_heap_ut.h"
#endif /* HSE_MOCKING */

#endif
