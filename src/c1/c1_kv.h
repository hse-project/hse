/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_KV_H
#define HSE_C1_KV_H

merr_t
c1_kvcache_create(struct c1 *c1);

void
c1_kvcache_destroy(struct c1 *c1);

#endif /* HSE_C1_KV_H */
