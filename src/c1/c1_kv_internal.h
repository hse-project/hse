/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_KV_INTERNAL_H
#define HSE_C1_KV_INTERNAL_H

void
c1_kvcache_destroy_internal(struct c1_kvcache *cc);

void
c1_kvbundle_reset(struct c1_kvbundle *ckvb);

void
c1_kvtuple_reset(struct c1_kvtuple *ckvt);

void
c1_vtuple_reset(struct c1_vtuple *cvt);

#endif /* HSE_C1_KV_INTERNAL_H */
