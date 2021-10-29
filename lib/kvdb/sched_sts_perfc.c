/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_sched_sts_perfc

#include <hse_util/perfc.h>

#include <hse/kvdb_perfc.h>

#include "sched_sts_perfc.h"

static struct perfc_name sts_perfc[] _dt_section = {

    NE(PERFC_BA_STS_QDEPTH, 3, "Queue depth", "qdepth"),

    NE(PERFC_RA_STS_JOBS, 3, "Jobs", "jobs"),
    NE(PERFC_BA_STS_JOBS_RUN, 3, "Running jobs", "jobs_running"),

    NE(PERFC_BA_STS_WORKERS, 3, "Workers", "workers"),
    NE(PERFC_BA_STS_WORKERS_IDLE, 3, "Idle Workers", "workers_idle"),
};

NE_CHECK(sts_perfc, PERFC_EN_STS, "sts perfc table/enum mismatch");

void
sts_perfc_alloc(uint prio, const char *group, const char *name, struct perfc_set *setp)
{
    perfc_alloc(sts_perfc, group, name, prio, setp);
}

void
sts_perfc_free(struct perfc_set *set)
{
    perfc_ctrseti_free(set);
}
