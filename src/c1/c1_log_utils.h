/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_LOG_UTILS_H
#define HSE_C1_LOG_UTILS_H

merr_t
c1_log_replay_open(struct c1_log *log, int type, u16 ver);

merr_t
c1_log_replay(struct c1_log *log, u64 ingestid, u16 ver);

void
c1_log_replay_close(struct c1_log *log, bool destroy);

merr_t
c1_log_diag_replay(struct c1_log *log, c1_journal_replay_cb *cb, void *cbarg, u16 ver);

static inline void
c1_log_keycount(struct c1_log *log, u64 *ingestcount, u64 *replaycount)
{
    assert(log);

    *ingestcount = atomic64_read(&log->c1l_ckcount);
    *replaycount = atomic64_read(&log->c1l_kcount);
}

#endif /* HSE_C1_LOG_UTILS_H */
