/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_DIAG_H
#define HSE_C1_DIAG_H

merr_t
c1_diag_replay_trees(struct c1 *c1, c1_journal_replay_cb *cb);

merr_t
c1_diag_replay_journal(struct c1 *c1, c1_journal_replay_cb *cb);

#endif /* HSE_C1_DIAG_H */
