/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_JRNL_UTILS_H
#define HSE_C1_JRNL_UTILS_H

merr_t
c1_journal_replay_default_cb(struct c1 *c1, u32 cmd, void *rec, void *rec2);

merr_t
c1_journal_replay_impl(struct c1 *c1, struct c1_journal *jrnl, c1_journal_replay_cb *cb);

#endif /* HSE_C1_JRNL_UTILS_H */
