/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVS_LIMITS_H
#define HSE_IKVS_LIMITS_H

/* clang-format off */

#define HSE_C0_CHEAP_SZ_MIN         (16ul << 20)
#define HSE_C0_CHEAP_SZ_DFLT        (16ul << 20)
#define HSE_C0_CHEAP_SZ_MAX         (64ul << 20)
#define HSE_C0_CCACHE_SZ_MAX        (4ul << 30)

/* HSE_C0_INGEST_WIDTH_DYN limits the max width of a normal, dynamically
 * sized kvms, whereas HSE_C0_INGEST_WIDTH_MAX limits the max width of
 * fixed size kvms (fixed either by rparams or via boosting, see
 * c0sk_ingest_tune() for details).
 */
#define HSE_C0_INGEST_WIDTH_MIN     (16)
#define HSE_C0_INGEST_WIDTH_DFLT    (16)
#define HSE_C0_INGEST_WIDTH_DYN     (20)
#define HSE_C0_INGEST_WIDTH_MAX     (32)

#define HSE_C0_INGEST_SZ_MAX        (2048) /* MiB */

#define HSE_C0_INGEST_THREADS_DFLT  (3)
#define HSE_C0_INGEST_THREADS_MAX   (5)

#define HSE_C0_MAINT_THREADS_DFLT   (5)
#define HSE_C0_MAINT_THREADS_MAX    (32)

/* The defines for the max number of entries in the viewset and snr
 * caches are totals for the entire cache.  Any given thread will
 * likely be able to access only a fraction of the total.
 */
#define HSE_VIEWSET_ELTS_MAX        (128ul << 10)
#define HSE_C0SNRSET_ELTS_MAX       (32ul << 20)

/* We use the c0kvms ptomb c0kvs cheap to store the c0kvms-priv and
 * c0 ingest-work buffers.  We desire to size the priv buffer such
 * that the total size of both the priv + ingest-work buffers are
 * less than the trim size.  We estimate a generous 128K for the
 * ingest-work buffer, sizeof(uintptr_t) for the priv buffer entry
 * size, and limit it to about 1 million entries.
 */
#define HSE_C0KVMS_C0SNR_MAX        (1536ul * 1024)

/* Limit the footprint of the cursor cache to the lesser of 10%
 * of available memory or 32GB.  The cursor cache is shared by
 * all open kvdbs within a single process.
 */
#define HSE_CURCACHE_SZ_PCT         (10)
#define HSE_CURCACHE_SZ_MIN         (2ul << 30)
#define HSE_CURCACHE_SZ_MAX         (32ul << 30)

/* Limit the footprint of active cursors within a kvdb
 * to the lesser of 10% of available memory or 32GB.
 */
#define HSE_CURACTIVE_SZ_PCT        (10)
#define HSE_CURACTIVE_SZ_MIN        (2ul << 30)
#define HSE_CURACTIVE_SZ_MAX        (32ul << 30)

/* A cursor's footprint is at least 1MB, not including iterators
 * (see struct kvs_cursor).
 */
#define HSE_CURSOR_SZ_MIN           (HSE_KVS_KLEN_MAX + HSE_KVS_VLEN_MAX)

/* Using any size other than 32MB will likely cause problems
 * due to the way space is allocated to wbtree internal nodes.
 */
#define KBLOCK_MIN_SIZE             (32ul << 20)
#define KBLOCK_MAX_SIZE             (32ul << 20)

/*
 * Maximum supported vblock size.
 */
#define VBLOCK_MIN_SIZE             (32ul << 20)
#define VBLOCK_MAX_SIZE             (32ul << 20)

/*
 * Min and max fanouts.
 */
#define CN_FANOUT_BITS_MIN          (1)
#define CN_FANOUT_BITS_MAX          (4)

#define CN_FANOUT_MIN               (1 << CN_FANOUT_BITS_MIN)
#define CN_FANOUT_MAX               (1 << CN_FANOUT_BITS_MAX)

#define CN_SMALL_VALUE_THRESHOLD    (8)

/* clang-format on */

#endif
