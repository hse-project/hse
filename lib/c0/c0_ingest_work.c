/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "c0_ingest_work.h"

#include <hse_util/platform.h>
#include <hse_util/bonsai_tree.h>

merr_t
c0_ingest_work_init(struct c0_ingest_work *c0iw)
{
    struct bin_heap2 *minheap;
    merr_t            err;

    assert(c0iw);

    memset(c0iw, 0, sizeof(*c0iw));
    c0iw->c0iw_magic = (uintptr_t)c0iw;
    c0iw->c0iw_tailp = &c0iw->c0iw_next;

    err = bin_heap2_create(HSE_C0_KVSET_ITER_MAX, bn_kv_cmp, &minheap);
    if (ev(err))
        return err;

    c0iw->c0iw_minheap = minheap;

    return 0;
}

void
c0_ingest_work_reset(struct c0_ingest_work *c0iw)
{
    assert(c0iw->c0iw_magic == (uintptr_t)c0iw);

    bin_heap2_reset(c0iw->c0iw_minheap);
    c0iw->c0iw_tailp = &c0iw->c0iw_next;
    *c0iw->c0iw_tailp = NULL;
    c0iw->c0iw_iterc = 0;
    c0iw->c0iw_coalescec = 0;

    memset(c0iw->c0iw_mbc, 0, sizeof(c0iw->c0iw_mbc));
    memset(c0iw->c0iw_mbv, 0, sizeof(c0iw->c0iw_mbv));
    memset(c0iw->c0iw_cmtv, 0, sizeof(c0iw->c0iw_cmtv));
    memset(c0iw->c0iw_coalscedkvms, 0, sizeof(c0iw->c0iw_coalscedkvms));
}

void
c0_ingest_work_fini(struct c0_ingest_work *w)
{
    if (!w)
        return;

    assert(w->c0iw_magic == (uintptr_t)w);
    w->c0iw_magic = 0xdeadc0de;

    BullseyeCoverageSaveOff

        if (w->t0 > 0)
    {
        struct c0_usage *u = &w->c0iw_usage;

        w->t3 = w->t3 > w->t0 ? w->t3 : w->t7;
        w->t4 = w->t4 > w->t3 ? w->t4 : w->t7;
        w->t5 = w->t5 > w->t4 ? w->t5 : w->t7;
        w->t6 = w->t6 > w->t5 ? w->t6 : w->t7;

        hse_log(
            HSE_WARNING "c0_ingest: gen %lu/%lu width %u/%u "
                        "keys %lu tombs %lu keyb %lu valb %lu "
                        "rcu %lu queue %lu bhprep %lu "
                        "c0ingest %lu %lu %lu "
                        "finish %lu cningest %lu destroy %lu total %lu",
            (ulong)w->gen,
            (ulong)w->gencur,
            w->c0iw_usage.u_count,
            w->c0iw_iterc,
            (ulong)(u->u_keys + u->u_tombs),
            (ulong)u->u_tombs,
            (ulong)u->u_keyb,
            (ulong)u->u_valb,
            (ulong)(w->c0iw_tenqueued - w->c0iw_tingesting) / 1000,
            (ulong)(w->t0 - w->c0iw_tenqueued) / 1000,
            (ulong)(w->t3 - w->t0) / 1000,
            (ulong)(w->t4 - w->t3) / 1000,
            (ulong)w->taddval / 1000,
            (ulong)w->taddkey / 1000,
            (ulong)(w->t5 - w->t4) / 1000,
            (ulong)(w->t6 - w->t5) / 1000,
            (ulong)(w->t7 - w->t6) / 1000,
            (ulong)(w->t7 - w->t0) / 1000);
    }

    BullseyeCoverageRestore

        bin_heap2_destroy(w->c0iw_minheap);
}
