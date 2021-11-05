/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_ATOMIC_H
#define HSE_PLATFORM_ATOMIC_H

#include <stdatomic.h>

/* clang-format off */

/* The following typedefs are remnants of a legacy implementation of this
 * API and are deprecated. New code should use one of the atomic types
 * from stdatomic.h, and existing code should be updated to use the
 * correct atomic type.
 */
typedef atomic_int      atomic_t;
typedef atomic_long     atomic64_t;


/* Relaxed semantics:
 *
 * No synchronization nor ordering guarantees.
 */
#define atomic_read(_ptr) \
    atomic_load_explicit((_ptr), memory_order_relaxed)

#define atomic_set(_ptr, _val) \
    atomic_store_explicit((_ptr), (_val), memory_order_relaxed)

#define atomic_add(_ptr, _val) \
    (void)atomic_fetch_add_explicit((_ptr), (_val), memory_order_relaxed)

#define atomic_sub(_ptr, _val) \
    (void)atomic_fetch_sub_explicit((_ptr), (_val), memory_order_relaxed)

#define atomic_inc(_ptr) \
    (void)atomic_fetch_add_explicit((_ptr), 1, memory_order_relaxed)

#define atomic_dec(_ptr) \
    (void)atomic_fetch_sub_explicit((_ptr), 1, memory_order_relaxed)


/* Acquire semantics:
 *
 * The operation must complete (in program order) before any subsequent
 * load or store is performed.
 */
#define atomic_read_acq(_ptr) \
    atomic_load_explicit((_ptr), memory_order_acquire)

#define atomic_inc_acq(_ptr) \
    (void)atomic_fetch_add_explicit((_ptr), 1, memory_order_acquire)

#define atomic_inc_acq_return(_ptr) \
    (atomic_fetch_add_explicit((_ptr), 1, memory_order_acquire) + 1)


/* Release semantics:
 *
 * All prior loads and stores (in program order across all cpus in
 * the system) must have completed before the operation is performed.
 */
#define atomic_set_rel(_ptr, _val) \
    atomic_store_explicit((_ptr), (_val), memory_order_release)

#define atomic_sub_rel(_ptr, _val) \
    (void)atomic_fetch_sub_explicit((_ptr), (_val), memory_order_release)

#define atomic_inc_rel(_ptr) \
    (void)atomic_fetch_add_explicit((_ptr), 1, memory_order_release)

#define atomic_dec_rel(_ptr) \
    (void)atomic_fetch_sub_explicit((_ptr), 1, memory_order_release)


#define atomic_and_rel(_ptr, _val) \
    (void)atomic_fetch_and_explicit((_ptr), (_val), memory_order_release)

#define atomic_or_rel(_ptr, _val) \
    (void)atomic_fetch_or_explicit((_ptr), (_val), memory_order_release)


/* Sequentially consistent semantics:
 *
 * Provides acquire semantics on load operations, release semantics on
 * store operations, and all threads see all stores in the same order.
 * This is the default behavior for all atomic operations unless a
 * memory order is explicitly specified.
 */
#define atomic_inc_return(_ptr) \
    (atomic_fetch_add((_ptr), 1) + 1)

#define atomic_dec_return(_ptr) \
    (atomic_fetch_sub((_ptr), 1) - 1)

#define atomic_cmpxchg(_ptr, _oldp, _new) \
    atomic_compare_exchange_strong((_ptr), (_oldp), (_new))

#define atomic_cas(_ptr, _old, _new)                            \
    ({                                                          \
        typeof(_ptr) ptr = (_ptr);                              \
        typeof(*ptr) exp = (_old);                              \
                                                                \
        atomic_compare_exchange_strong(ptr, &exp, (_new));      \
    })

/* clang-format on */

#endif /* HSE_PLATFORM_ATOMIC_H */
