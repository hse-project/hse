/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_MBLK_H
#define HSE_C1_MBLK_H

struct mpool;
struct c1_mblk;

merr_t
c1_mblk_create(struct mpool *ds, struct c1_mblk **mblkout);

void
c1_mblk_destroy(struct c1_mblk *mblk);

merr_t
c1_mblk_get_val(struct c1_mblk *mblk, u64 blkid, u64 blkoff, void **valuep, u64 vlen);

void
c1_mblk_put_val(struct c1_mblk *mblk, u64 blkid, u64 blkoff, void *valuep, u64 vlen);

#endif /* HSE_C1_MBLK_H */
