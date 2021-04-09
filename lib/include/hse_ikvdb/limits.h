/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVS_LIMITS_H
#define HSE_IKVS_LIMITS_H

#define HSE_C0_CHEAP_SZ_MIN (1024 * 1024 * 8ul)
#define HSE_C0_CHEAP_SZ_DFLT (1024 * 1024 * 8ul)
#define HSE_C0_CHEAP_SZ_MAX (1024 * 1024 * 256ul)
#define HSE_C0_CCACHE_SZ_MAX (1024 * 1024 * 1024 * 16ul)
#define HSE_C0_CCACHE_TRIMSZ (HSE_C0_CHEAP_SZ_MIN * 4)

#define HSE_C0_BNODE_SLAB_SZ (PAGE_SIZE * 4)

/* HSE_C0_INGEST_WIDTH_DYN limits the max width of a normal, dynamically
 * sized kvms, whereas HSE_C0_INGEST_WIDTH_MAX limits the max width of
 * fixed size kvms (fixed either by rparams or via boosting, see
 * c0sk_ingest_tune() for details).
 */
#define HSE_C0_INGEST_WIDTH_MIN     (8)
#define HSE_C0_INGEST_WIDTH_DFLT    (8)
#define HSE_C0_INGEST_WIDTH_DYN     (20)
#define HSE_C0_INGEST_WIDTH_MAX     (HSE_C0_INGEST_WIDTH_DYN + 12)

#define HSE_C0_INGEST_DELAY_DFLT (0)
#define HSE_C0_INGEST_SZ_MAX (2048) /* MiB */

#define HSE_C0_INGEST_THREADS_DFLT (3)
#define HSE_C0_INGEST_THREADS_MAX (8)

#define HSE_C0_MAINT_THREADS_DFLT (5)
#define HSE_C0_MAINT_THREADS_MAX (32)

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
#define HSE_C0KVMS_C0SNR_MAX min(((HSE_C0_CCACHE_TRIMSZ - (128ul * 1024)) / 8), 1280ul * 1024)

/* Using any size other than 32MB will likely cause problems
 * due to the way space is allocated to wbtree internal nodes.
 */
#define KBLOCK_MIN_SIZE (32 * 1024 * 1024)
#define KBLOCK_MAX_SIZE (32 * 1024 * 1024)

/*
 * Maximum supported vblock size.
 */
#define VBLOCK_MIN_SIZE (32 * 1024 * 1024)
#define VBLOCK_MAX_SIZE (32 * 1024 * 1024)

/*
 * Min and max fanouts.
 */
#define CN_FANOUT_BITS_MIN (1)
#define CN_FANOUT_BITS_MAX (4)

#define CN_FANOUT_MIN (1 << CN_FANOUT_BITS_MIN)
#define CN_FANOUT_MAX (1 << CN_FANOUT_BITS_MAX)

#define CN_SMALL_VALUE_THRESHOLD (8)

#endif
