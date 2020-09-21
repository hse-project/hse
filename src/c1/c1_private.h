/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_PRIVATE_H
#define HSE_C1_PRIVATE_H

/*
 * Implementation of c1 - The durability layer of kvdb
 *-----------------------------------------------------
 *
 * Physical storage: The c1 is backed by one MDC and one or more mlogs. This
 * layer is divided into two components.
 *
 * 1. Journal (MDC)
 * The MDC saves durability requirements such as time, size  etc.
 * Additionally it stores c1's journal containing the descriptions of mlogs
 * that persists the actual keys and values.
 *
 * 2 c1 tree (collection of mlogs)
 * The mlogs that saves keys/values are organized into one or more c1 trees.
 * Each c1 tree is a collection of mlogs of count C1_DEFAULT_STRIPE_WIDTH.
 * This constant if the need arises can be replaced with a static or
 * dynamic tunable. The mlogs are of equal size and the size of mlogs
 * determines the largest transaction a tree can accomodate.
 *
 * Each c1 tree itself saves a consistent kvdb image/checkpoint. The logic
 * ensures that the contents of transactions are committed entirely in
 * a single tree to ensure the all-or-nothing behavior of transactions.
 * When a tree is full, a new tree is allocated to serve ingests. c1 trees
 * are versioned. The OMF of c1 tree contain sequence and generation numbers
 * for this purpose. The tree having least sequence/generation number is the
 * oldest tree - e.g. (7,0) is older than (7, 1) and (10.2).
 *
 * c1 tree life cycle:
 * Each tree goes through several stages in its life cycle. It is "NEW" when
 * it is freshly allocated. Then it becomes "INUSE" containing one or more
 * key/value(s). It becomes clean when one or more cN ingests makes its content
 * redundant, but it is still useable to serve reads if needed. Then it gets
 * into "REUSE" or "RECYCLE"  stage when c1 storage limits are reached.
 * Currently having no read (GET) support, it recycles older trees as soon as
 * the cN ingest(s) make their contents redundant. This design is chosen for
 * faster tree allocation by reuse. When a tree is reused, a journal entry
 * is made to record the state transition.
 *
 * Ingest path - Grabs the latest tree for ingesting keys/values. If it does
 * not have enough space then, the current tree will be marked as full. The
 * it tries to find to reuse a tree. There is nothing to be reused then it
 * will allocate new tree. The allocation of a new tree requires creating
 * and formatting one or more mlogs. The mlogs of a tree are chosen on a
 * round-robin fashion using first-fit method.
 *
 * Replay path - For iterim use, c1 leverages the replay code path of WAL,
 * wherein the contents are ingested back into c0 for cN ingests. This will
 * be revisited in a future phase of c1.
 */

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/event_counter.h>
#include <hse_util/timing.h>
#include <hse_util/logging.h>
#include <hse_util/atomic.h>
#include <hse_util/mutex.h>
#include <hse_util/condvar.h>
#include <hse_util/perfc.h>
#include <hse_util/alloc.h>

#include <hse/kvdb_perfc.h>
#include <hse/hse.h>

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/c1.h>
#include <hse_ikvdb/c1_replay.h>
#include <hse_ikvdb/ikvdb.h>

#include "c1_omf.h"
#include "c1_ops.h"
#include "c1_utils.h"
#include "c1_log.h"
#include "c1_log_utils.h"
#include "c1_tree.h"
#include "c1_tree_utils.h"
#include "c1_journal.h"
#include "c1_journal_utils.h"
#include "c1_compact.h"
#include "c1_io.h"
#include "c1_perfc.h"
#include "c1_txn.h"

#include "c1_kv.h"

#define MB (1024UL * 1024)
#define GB (1024UL * MB)
#define HSE_C1_TREE_CNT_LB 0
#define HSE_C1_TREE_CNT_UB 10
#define HSE_C1_DEFAULT_THREAD_CNT HSE_C1_DEFAULT_STRIPE_WIDTH
#define HSE_C1_DEFAULT_STRIP_SIZE (32 * 1024)
#define HSE_C1_MIN_DTIME 50          /* 50 ms */
#define HSE_C1_DEFAULT_DTIME 500     /* 500 ms */
#define HSE_C1_MAX_DTIME (60 * 1000) /* 60 seconds */
#define HSE_C1_DEFAULT_DSIZE (35 * MB)
#define HSE_C1_MAX_CAP (16 * GB)
#define HSE_C1_MIN_CAP (4 * GB)
#define HSE_C1_DEFAULT_CAP (6 * GB)
#define HSE_C1_MIN_CACHESIZE 10

#endif /* HSE_C1_PRIVATE_H */
