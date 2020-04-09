/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/* Stubs for compaction scheduler in kernel */

#include <hse_ikvdb/sched_sts.h>

merr_t
sts_create(struct kvdb_rparams *rp, const char *name, uint nq, struct sts **sched)
{
    *sched = (void *)-1;
    return 0;
}

void
sts_destroy(struct sts *s)
{
}

void
sts_cancel_jobs(struct sts *s, u64 tag)
{
}

void
sts_job_submit(struct sts *s, struct sts_job *job)
{
}

void
sts_wcnt_set_target(struct sts *s, uint qnum, uint target)
{
}

uint
sts_wcnt_get_target(struct sts *s, uint qnum)
{
    return 0;
}

uint
sts_wcnt_get_idle(struct sts *s, uint qnum)
{
    return 0;
}

void
sts_pause(struct sts *s)
{
}

void
sts_resume(struct sts *s)
{
}
