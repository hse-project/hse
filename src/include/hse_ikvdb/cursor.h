/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CURSOR_H
#define HSE_KVS_CURSOR_H

#include <hse_util/inttypes.h>

/**
 * per-cursor diagnostic summary
 *
 * @addr:     address of this cursor (should be found in cache after use)
 * @dgen[]:   circular buffer of last 4 dgen in this cursor
 * @horiz:    the cn horizon when this cursor was last updated (last dgen)
 * @view:     the cursor's view seqno
 * @read_c0:  number of reads satisfied by c0
 * @read_cn:  number of reads satisfied by cN
 * @n_kvset:  number of cN kvsets in cursor when last updated
 * @n_kvms:   number of c0 kvms in cursor when last updated
 * @n_trim:   number of c0 kvms trimmed due to ingest
 * @n_update: number of times this cursor updated (saturates at 256)
 * @n_bind:   number of times this cursor bound (saturates at 256)
 * @n_dgen:   number of new dgen seen, last 2 bits record circular buffer loc
 *
 * This per-cursor structure is shared by ikvs, c0 and cn.
 * It is copied to a cache and optionally output upon destroy.
 *
 * The intention of this is to allow some type of capture of what a
 * cursor's state was at destroy time (typically the point of failure).
 * By also logging this structure as a single message, the destroy and/or
 * create can be compared to ingest for timing related events.  By caching
 * the last N of these, a debugger -- or perhaps a rest api -- can get a
 * view of recent cursor activity (such as when the cursor in error has
 * been cached and restored, or if the frequency is too high to log each
 * cursor restore/save event).
 */

struct cursor_summary {
    void *addr;     /* ikvs */
    u64   created;  /* ikvs */
    u64   updated;  /* ikvs */
    u64   dgen[4];  /* cn */
    u64   seqno;    /* ikvs */
    u32   read_c0;  /* ikvs */
    u32   read_cn;  /* ikvs */
    u32   util;     /* ikvs */
    u16   n_kvset;  /* cn */
    u8    n_kvms;   /* c0sk */
    u8    n_trim;   /* c0sk */
    u8    n_bind;   /* ikvs */
    u8    n_update; /* ikvs */
    u8    n_dgen;   /* cn */
    u8    skidx;    /* c0sk */
                    /* flags? created c0, cn, restored c0, cn? */
} __packed;

static inline void
cursor_summary_add_dgen(struct cursor_summary *sum, u64 dgen)
{
    if (dgen != sum->dgen[(sum->n_dgen - 1) & 3])
        sum->dgen[sum->n_dgen++ & 3] = dgen;
}

#endif
