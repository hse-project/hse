/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_CSCHED_RP_H
#define HSE_IKVDB_CSCHED_RP_H

/*
 * This file contains macros for decoding csched related runtime parameters.
 */
static inline u64
csched_bits_get(u64 word, uint shift, u64 mask)
{
    return (word >> shift) & mask;
}

static inline u64
csched_bits_set(u64 word, uint shift, u64 mask, u64 bits)
{
    return (word & ~(mask << shift)) | ((bits & mask) << shift);
}

/* csched_policy run-time parameter:
 *
 *    Byte 7: Unused
 *    Byte 6: Unused
 *    Byte 5: Unused
 *    Byte 4: Unused
 *    Byte 3: Unused
 *    Byte 2: Unused
 *    Byte 1: Mblock data access method
 *            bits 0x03:
 *              0 : async mblock read
 *              1 : sync mblock read
 *              2 : mcache maps
 *    Byte 0: Policy Selector
 *            0:    Used old (non)scheduler
 *            1:    Policy 1 (compatibility mode)
 *            2:    Policy 2 (no longer supported)
 *            3:    Policy 3 (space amp scheduler)
 *            0xff: No-op scheduler
 */

#define CSCHED_RP_KVSET_ITER_SHIFT 8
#define CSCHED_RP_KVSET_ITER_MASK  0x03

#define CSCHED_RP_POLICY_SHIFT 0
#define CSCHED_RP_POLICY_MASK  0xff

/* runtime param to get kvset iterator behavior */
#define csched_rp_kvset_iter(_rp) \
    csched_bits_get((_rp)->csched_policy, CSCHED_RP_KVSET_ITER_SHIFT, CSCHED_RP_KVSET_ITER_MASK)

/* values for two-bit kvset iter field */
#define csched_rp_kvset_iter_async  0
#define csched_rp_kvset_iter_sync   1
#define csched_rp_kvset_iter_mcache 2

/* runtime param to get policy (ingored after kvdb_open) */
#define csched_rp_policy(_rp) \
    csched_bits_get((_rp)->csched_policy, CSCHED_RP_POLICY_SHIFT, CSCHED_RP_POLICY_MASK)

/* Compaction stats */
#define csched_rp_dbg_comp(_rp) ((_rp)->csched_debug_mask & 0x000f)

/* SP3 Debug */
#define csched_rp_dbg_qos(_rp)   ((bool)((_rp)->csched_debug_mask & 0x0010))
#define csched_rp_dbg_sched(_rp) ((bool)((_rp)->csched_debug_mask & 0x0020))
#define csched_rp_dbg_job(_rp)   ((bool)((_rp)->csched_debug_mask & 0x0040))
#define csched_rp_dbg_jobv(_rp)  ((bool)((_rp)->csched_debug_mask & 0x0080))

#define csched_rp_dbg_samp_work(_rp)   ((bool)((_rp)->csched_debug_mask & 0x0100))
#define csched_rp_dbg_samp_ingest(_rp) ((bool)((_rp)->csched_debug_mask & 0x0200))
#define csched_rp_dbg_dirty_node(_rp)  ((bool)((_rp)->csched_debug_mask & 0x0400))
#define csched_rp_dbg_tree_life(_rp)   ((bool)((_rp)->csched_debug_mask & 0x0800))

#define csched_rp_dbg_rbtree(_rp) ((bool)((_rp)->csched_debug_mask & 0x1000))

/* STS Debug */
#define csched_rp_dbg_jobs(_rp)   ((bool)((_rp)->csched_debug_mask & 0x2000))
#define csched_rp_dbg_mon(_rp)    ((bool)((_rp)->csched_debug_mask & 0x4000))
#define csched_rp_dbg_worker(_rp) ((bool)((_rp)->csched_debug_mask & 0x8000))

#endif
