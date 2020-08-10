/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_RCU_H
#define HSE_PLATFORM_RCU_H

#define _LGPL_SOURCE

#include <urcu-bp.h>
#include <urcu/rculist.h>

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

#include <hse_util/cds_list.h>

#endif
