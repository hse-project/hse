/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_VBUILDER_INTERNAL_H
#define HSE_C1_VBUILDER_INTERNAL_H

bool
c1_kvset_builder_abort_ingest(struct c1_kvset_builder_elem *bldrs);

void
c1_kvset_builder_elem_put_int(
    struct c1_kvset_builder *     bldrs,
    struct c1_kvset_builder_elem *elem,
    bool                          need_lock,
    bool                          final);

merr_t
c1_kvset_builder_elem_get_int(
    struct c1_kvset_builder *      bldrs,
    u64                            gen,
    struct c1_kvset_builder_elem **elemout);

#endif /* HSE_C1_VBUILDER_INTERNAL_H */
