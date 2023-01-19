/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_C0_KVSET_ITERATOR_H
#define HSE_CORE_C0_KVSET_ITERATOR_H

#include <stdint.h>

#include <hse/error/merr.h>
#include <hse/ikvdb/lc.h>
#include <hse/util/bonsai_tree.h>
#include <hse/util/element_source.h>

/**
 * c0_kvset_iterator - c0kvs iterator (used for in order traversal)
 * @c0it_handle:     Handle to the iterator
 * @c0it_root:       Root of cbtree (for seek)
 * @c0it_next:       Next element for foward traversal
 * @c0it_prev:       Next element for reverse traversal
 *
 * c0_kvset_iterator is a bi-directional iterator which can be used to move
 * both forward and backward within the c0kvs for which it was initialized.
 * Note, however, that when using the element source interface, the container
 * may be traversed in only the direction specified by the iterator init
 * function.
 */
struct c0_kvset_iterator {
    struct element_source c0it_handle;
    struct bonsai_root *c0it_root;
    struct bonsai_kv *c0it_next;
    struct bonsai_kv *c0it_prev;
    uint c0it_flags;
    int c0it_index;
};

#define C0_KVSET_ITER_FLAG_REVERSE 0x0001
#define C0_KVSET_ITER_FLAG_PTOMB   0x0002
#define C0_KVSET_ITER_FLAG_INDEX   0x0004

struct kvs_ktuple;

/**
 * c0_kvset_iterator_init() - Initialize element source iterator for a c0_kvset
 * @iter:       handle to the allocated c0_kvset_iterator
 * @root:       root of cbtree
 * @flags:      input flags
 *              default: 0  forward iterator that doesn't filter on index and
 *                          which iterates over a non ptomb c0_kvset
 *              C0_KVSET_ITER_FLAG_REVERSE: reverse iterator
 *              C0_KVSET_ITER_FLAG_PTOMB:   iterates over a ptomb c0_kvset
 *              C0_KVSET_ITER_FLAG_INDEX:   filter on index (skidx)
 * @index:      index that this iterator should filter on (currently skidx)
 *              applies only if C0_KVSET_ITER_FLAG_INDEX flag is set
 *
 * Initialize an iterator for traversing the data elements (i.e., cb_kv)
 * of the specified container from lowest to highest key.
 */
void
c0_kvset_iterator_init(
    struct c0_kvset_iterator *iter,
    struct bonsai_root *root,
    uint flags,
    int index);

/**
 * c0_kvset_iterator_empty() - check to see if container is empty
 * @handle:     c0_kvset iterator handle
 *
 * Return: %true if container for which the iterator was initialized
 * is empty, otherwise %false.  This function gives no indication as
 * to the position of the iterator within the container.
 */
bool
c0_kvset_iterator_empty(struct c0_kvset_iterator *handle);

/**
 * c0_kvset_iterator_eof() - check to see if container is at eof
 * @handle:     c0_kvset iterator handle
 *
 * Return: %true if container for which the iterator was initialized
 * is at eof at this instant, otherwise %false.
 */
bool
c0_kvset_iterator_eof(struct c0_kvset_iterator *handle);

/**
 * c0_kvset_iterator_seek() - move iteration next to %seek argument
 * @iter:            c0_kvset iterator
 * @seek:            the key to find
 * @seeklen:         length of seek
 * @kt:              optional: which key we found
 *
 * Re-initializes the iterator to start at @seek.  The next key will
 * be in the direction of the iterator when first initialized.
 * If the seek key is not found, the next lexicographic key in the
 * iterator direction will be used.  If @kt is not null, it will be
 * initialized to point to the key found.
 */
void
c0_kvset_iterator_seek(
    struct c0_kvset_iterator *iter,
    const void *seek,
    uint32_t seeklen,
    struct kvs_ktuple *kt);

/**
 * c0_kvset_iterator_get_es() -
 * @handle:     c0_kvset iterator handle
 *
 * Return: pointer to element source interface to c0_kvset iterator
 */
struct element_source *
c0_kvset_iterator_get_es(struct c0_kvset_iterator *handle);

#endif
