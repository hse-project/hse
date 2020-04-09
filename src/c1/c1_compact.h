/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_COMPACT_H
#define HSE_C1_COMPACT_H

/* MTF_MOCK_DECL(c1_compact) */

merr_t
c1_compact(struct c1 *c1);

/* MTF_MOCK */
merr_t
c1_compact_new_trees(struct c1 *c1);

/* MTF_MOCK */
merr_t
c1_compact_inuse_trees(struct c1 *c1);

/* MTF_MOCK */
merr_t
c1_compact_reset_trees(struct c1 *c1);

/* MTF_MOCK */
merr_t
c1_compact_clean_trees(struct c1 *c1);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "c1_compact_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif /* HSE_C1_COMPACT_H */
