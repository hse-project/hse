/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_RCU_H
#define HSE_PLATFORM_RCU_H

#define _LGPL_SOURCE

/*
 * This snippet exists as a proxy to solve release buildtype issues due to
 * unread/unused variable warnings in urcu/wfcqueue.h.
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wunused-variable"

#include <urcu-bp.h>
#include <urcu/rculist.h>

#pragma GCC diagnostic pop

#ifdef rcu_barrier
#define HSE_HAVE_RCU_BARRIER 1
#else
#define rcu_barrier rcu_barrier_bp

void
rcu_barrier_bp(void);
#endif

#ifndef rcu_read_ongoing
#define rcu_read_ongoing() true
#endif

#endif
