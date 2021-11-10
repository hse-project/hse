/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/rcu.h>

#if !HSE_HAVE_RCU_BARRIER

/* RHEL 7.4 and 7.5 prereq very old urcu implementations that do not include
 * rcu_barrier() nor rcu_read_ongoing().
 *
 * [MU_REVIST] Currently, only hse unit tests call rcu_barrier(), but it should
 * probably be called by c0sk_close() and mpc_exit().  A full implementation
 * of rcu_barrier() should invoke call_rcu() for each vCPU and wait for all
 * to complete.  The implementation here is incomplete as it only invokes
 * call_rcu() on at most one vCPU.
 */

#include <hse_util/atomic.h>

struct rcu_barrier_data {
    struct rcu_head rbd_rcu;
    atomic_int      rbd_count;
};

static void
rcu_barrier_cb(struct rcu_head *rh)
{
    struct rcu_barrier_data *rbd;

    rbd = caa_container_of(rh, struct rcu_barrier_data, rbd_rcu);

    atomic_inc_rel(&rbd->rbd_count);
}

__attribute__((__weak__)) void
rcu_barrier_bp(void)
{
    struct rcu_barrier_data rbd = {};

    call_rcu(&rbd.rbd_rcu, rcu_barrier_cb);

    rcu_defer_barrier();

    while (atomic_read_acq(&rbd.rbd_count) == 0)
        usleep(1000);

    synchronize_rcu();
}

#endif
