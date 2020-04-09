/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_VBLDR_H
#define HSE_C1_VBLDR_H

/* MTF_MOCK_DECL(c1_vbuilder) */
struct c1_kvset_builder;
struct c1_kvset_builder_elem;
struct c0sk;

merr_t
c1_kvset_builder_create(struct c0sk *c0sk, struct c1_kvset_builder **bldrsout);
void
c1_kvset_builder_destroy(struct c1_kvset_builder *bldrs);

/* MTF_MOCK */
merr_t
c1_kvset_vbuilder_acquire(struct c1_kvset_builder *bldrs, u64 gen, struct kvset_builder ***bldrout);

/* MTF_MOCK */
void
c1_kvset_vbuilder_release(struct c1_kvset_builder *bldrs, u64 gen);

/* MTF_MOCK */
merr_t
c1_kvset_builder_add_val(
    struct c1_kvset_builder_elem *bldrs,
    u32                           skidx,
    u64                           cnid,
    u64                           seqno,
    void *                        vdata,
    u64                           vlen,
    u8                            index,
    u64 *                         vbgenout,
    u64 *                         vbidout,
    u32 *                         vbidxout,
    u32 *                         vboffout,
    struct kvset_builder **       vbkvsbldrout);

/* MTF_MOCK */
merr_t
c1_kvset_builder_flush(struct c1_kvset_builder *bldrs);

merr_t
c1_kvset_builder_elem_create(
    struct c1_kvset_builder *      bldrs,
    u64                            gen,
    struct c1_kvset_builder_elem **elemout);

void
c1_kvset_builder_elem_put(struct c1_kvset_builder *bldrs, struct c1_kvset_builder_elem *elem);

bool
c1_kvset_builder_elem_valid(struct c1_kvset_builder_elem *elem, u64 gen);

/* MTF_MOCK */
merr_t
c1_kvset_builder_flush_elem(struct c1_kvset_builder_elem *bldrs, u8 index);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "c1_vbuilder_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif /* HSE_C1_VBLDR_H */
