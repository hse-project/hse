/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020,2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_CSCHED_RP_H
#define HSE_IKVDB_CSCHED_RP_H

/* runtime param to get kvset iterator behavior */
#define csched_rp_kvset_iter(_rp)   ((_rp)->csched_policy)

#define csched_rp_kvset_iter_async 0
#define csched_rp_kvset_iter_sync 1
#define csched_rp_kvset_iter_mcache 2

/* Compaction stats */
#define csched_rp_dbg_comp(_rp) ((_rp)->csched_debug_mask & 0x000f)

/* SP3 Debug */
#define csched_rp_dbg_qos(_rp) ((bool)((_rp)->csched_debug_mask & 0x0010))
#define csched_rp_dbg_sched(_rp) ((bool)((_rp)->csched_debug_mask & 0x0020))

#define csched_rp_dbg_samp_work(_rp) ((bool)((_rp)->csched_debug_mask & 0x0100))
#define csched_rp_dbg_samp_ingest(_rp) ((bool)((_rp)->csched_debug_mask & 0x0200))
#define csched_rp_dbg_dirty_node(_rp) ((bool)((_rp)->csched_debug_mask & 0x0400))
#define csched_rp_dbg_tree_life(_rp) ((bool)((_rp)->csched_debug_mask & 0x0800))

#define csched_rp_dbg_rbtree(_rp) ((bool)((_rp)->csched_debug_mask & 0x1000))

/* STS Debug */
#define csched_rp_dbg_mon(_rp) ((bool)((_rp)->csched_debug_mask & 0x4000))

#endif
