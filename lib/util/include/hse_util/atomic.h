/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_ATOMIC_H
#define HSE_PLATFORM_ATOMIC_H

/*
 * This file provides user-space implementations of the following Linux
 * kernel atomic operations:
 *
 *     32-bit atomics operations    64-bit atomic operations
 *     -------------------------    ------------------------
 *     atomic_read                  atomic64_read
 *     atomic_set                   atomic64_set
 *     atomic_add_return            atomic64_add_return
 *     atomic_sub_return            atomic64_sub_return
 *     atomic_add                   atomic64_add
 *     atomic_sub                   atomic64_sub
 *     atomic_inc                   atomic64_inc
 *     atomic_dec                   atomic64_dec
 *     atomic_add_negative          atomic64_add_negative
 *     atomic_sub_and_test          atomic64_sub_and_test
 *     atomic_dec_and_test          atomic64_dec_and_test
 *     atomic_inc_and_test          atomic64_inc_and_test
 *     atomic_inc_return            atomic64_inc_return
 *     atomic_dec_return            atomic64_dec_return
 *     atomic_fetch_add             atomic64_fetch_add
 *     atomic_cmpxchg               atomic64_cmpxchg
 *
 *
 * Notes:
 *  - This file implements a limited subset of kernel atomic operations.
 *  - The atomics implemented in this file use GCC's atomic bultins and
 *    are probably not as performant as the kernel atomics.  If
 *    performance becomes an issue, look at the open source
 *    libatomic_ops library.
 */

#include <hse_util/compiler.h>

typedef struct {
    int counter;
} atomic_t;

typedef struct {
    long counter;
} atomic64_t;

#define ATOMIC_INIT(i) \
    {                  \
        (i)            \
    }

#define ATOMIC64_INIT(i) \
    {                    \
        (i)              \
    }

/*----------------------------------------------------------------
 * 32-bit atomics
 */

/*
 * Atomically reads the value of @v.
 * Doesn't imply a read memory barrier.
 */
static inline int
atomic_read(const atomic_t *v)
{
    return __atomic_load_n(&v->counter, __ATOMIC_RELAXED);
}

/*
 * Atomically sets the value of @v to @i.
 * Doesn't imply a read memory barrier.
 */
static inline void
atomic_set(atomic_t *v, int i)
{
    __atomic_store_n(&v->counter, i, __ATOMIC_RELAXED);
}

/* Atomically adds @i to @v and returns @i + @v */
static inline int
atomic_add_return(int i, atomic_t *v)
{
    return __atomic_add_fetch(&v->counter, i, __ATOMIC_RELAXED);
}

/* Atomically subtracts @i from @v and returns @v - @i */
static inline int
atomic_sub_return(int i, atomic_t *v)
{
    return __atomic_sub_fetch(&v->counter, i, __ATOMIC_RELAXED);
}

/* Atomically adds @i to @v. */
static inline void
atomic_add(int i, atomic_t *v)
{
    (void)__atomic_fetch_add(&v->counter, i, __ATOMIC_RELAXED);
}

/* Atomically subtracts @i from @v. */
static inline void
atomic_sub(int i, atomic_t *v)
{
    (void)__atomic_fetch_sub(&v->counter, i, __ATOMIC_RELAXED);
}

static inline void
atomic_sub_rel(int i, atomic_t *v)
{
    (void)__atomic_fetch_sub(&v->counter, i, __ATOMIC_RELEASE);
}

/* Atomically increments @v by 1. */
static inline void
atomic_inc(atomic_t *v)
{
    (void)__atomic_fetch_add(&v->counter, 1, __ATOMIC_RELAXED);
}

/* Atomically decrements @v by 1. */
static inline void
atomic_dec(atomic_t *v)
{
    (void)__atomic_fetch_sub(&v->counter, 1, __ATOMIC_RELAXED);
}

/*
 * Atomically adds @i to @v and returns true if the result is negative,
 * or false when result is greater than or equal to zero.
 */
static inline int
atomic_add_negative(int i, atomic_t *v)
{
    return __atomic_add_fetch(&v->counter, i, __ATOMIC_RELAXED) < 0;
}

/*
 * Atomically subtracts @i from @v and returns true if the result is
 * zero, or false for all other cases.
 */
static inline int
atomic_sub_and_test(int i, atomic_t *v)
{
    return __atomic_sub_fetch(&v->counter, i, __ATOMIC_RELAXED) == 0;
}

/*
 * Atomically decrements @v by 1 and returns true if the result is 0, or
 * false for all other cases.
 */
static inline int
atomic_dec_and_test(atomic_t *v)
{
    return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_RELAXED) == 0;
}

/*
 * Atomically increments @v by 1 and returns true if the result is zero,
 * or false for all other cases.
 */
static inline int
atomic_inc_and_test(atomic_t *v)
{
    return __atomic_add_fetch(&v->counter, 1, __ATOMIC_RELAXED) == 0;
}

static inline int
atomic_inc_return(atomic_t *v)
{
    return __atomic_add_fetch(&v->counter, 1, __ATOMIC_RELAXED);
}

static inline int
atomic_dec_return(atomic_t *v)
{
    return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_RELAXED);
}

/*
 * Atomically return the current value of *v and then perform *v = *v + i
 */
static inline int
atomic_fetch_add(int i, atomic_t *v)
{
    return __atomic_fetch_add(&v->counter, i, __ATOMIC_RELAXED);
}

/*
 * Atomically sets v to newv if it was equal to oldv and returns the old value.
 */
static inline int
atomic_cmpxchg(atomic_t *v, int oldv, int newv)
{
    int retv = oldv;

    __atomic_compare_exchange_n(&v->counter, &retv, newv, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);

    return retv;
}

static inline _Bool
atomic_cas(atomic_t *v, int oldv, int newv)
{
    int retv = oldv;

    return __atomic_compare_exchange_n(
        &v->counter, &retv, newv, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

/*----------------------------------------------------------------
 * 64-bit atomics
 */

/*
 * Atomically reads the value of @v.
 * Doesn't imply a read memory barrier.
 */
static inline long
atomic64_read(const atomic64_t *v)
{
    return __atomic_load_n(&v->counter, __ATOMIC_RELAXED);
}

/*
 * Atomically sets the value of @v to @i.
 * Doesn't imply a read memory barrier.
 */
static inline void
atomic64_set(atomic64_t *v, long i)
{
    __atomic_store_n(&v->counter, i, __ATOMIC_RELAXED);
}

/* Atomically adds @i to @v and returns @i + @v */
static inline long
atomic64_add_return(long i, atomic64_t *v)
{
    return __atomic_add_fetch(&v->counter, i, __ATOMIC_RELAXED);
}

/* Atomically subtracts @i from @v and returns @v - @i */
static inline long
atomic64_sub_return(long i, atomic64_t *v)
{
    return __atomic_sub_fetch(&v->counter, i, __ATOMIC_RELAXED);
}

/* Atomically adds @i to @v. */
static inline void
atomic64_add(long i, atomic64_t *v)
{
    (void)__atomic_fetch_add(&v->counter, i, __ATOMIC_RELAXED);
}

/* Atomically subtracts @i from @v. */
static inline void
atomic64_sub(long i, atomic64_t *v)
{
    (void)__atomic_fetch_sub(&v->counter, i, __ATOMIC_RELAXED);
}

/* Atomically increments @v by 1. */
static inline void
atomic64_inc(atomic64_t *v)
{
    (void)__atomic_fetch_add(&v->counter, 1, __ATOMIC_RELAXED);
}

/* Atomically decrements @v by 1. */
static inline void
atomic64_dec(atomic64_t *v)
{
    (void)__atomic_fetch_sub(&v->counter, 1, __ATOMIC_RELAXED);
}

/*
 * Atomically adds @i to @v and returns true if the result is negative,
 * or false when result is greater than or equal to zero.
 */
static inline long
atomic64_add_negative(long i, atomic64_t *v)
{
    return __atomic_add_fetch(&v->counter, i, __ATOMIC_RELAXED) < 0;
}

/*
 * Atomically subtracts @i from @v and returns true if the result is
 * zero, or false for all other cases.
 */
static inline int
atomic64_sub_and_test(long i, atomic64_t *v)
{
    return __atomic_sub_fetch(&v->counter, i, __ATOMIC_RELAXED) == 0;
}

/*
 * Atomically decrements @v by 1 and returns true if the result is 0, or
 * false for all other cases.
 */
static inline int
atomic64_dec_and_test(atomic64_t *v)
{
    return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_RELAXED) == 0;
}

/*
 * Atomically increments @v by 1 and returns true if the result is zero,
 * or false for all other cases.
 */
static inline int
atomic64_inc_and_test(atomic64_t *v)
{
    return __atomic_add_fetch(&v->counter, 1, __ATOMIC_RELAXED) == 0;
}

static inline long
atomic64_inc_return(atomic64_t *v)
{
    return __atomic_add_fetch(&v->counter, 1, __ATOMIC_RELAXED);
}

static inline long
atomic64_dec_return(atomic64_t *v)
{
    return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_RELAXED);
}

/*
 * Atomically return the current value of *v and then perform *v = *v + i
 * [HSE_REVISIT] Should this be __ATOMIC_SEQ_CST? (transactions)
 */
static inline long
atomic64_fetch_add(long i, atomic64_t *v)
{
    return __atomic_fetch_add(&v->counter, i, __ATOMIC_RELAXED);
}

/*
 * Atomically sets v to newv if it was equal to oldv and returns the old value.
 */
static inline long
atomic64_cmpxchg(atomic64_t *v, long oldv, long newv)
{
    long retv = oldv;

    __atomic_compare_exchange_n(&v->counter, &retv, newv, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);

    return retv;
}

static inline _Bool
atomic64_cas(atomic64_t *v, long oldv, long newv)
{
    long retv = oldv;

    return __atomic_compare_exchange_n(
        &v->counter, &retv, newv, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}


/*
 * atomic_ptr_cmpxchg()
 *
 * if (*ptr == oldv):
 *     *ptr = newv
 *     return newv
 * else
 *     return *ptr (previous contents, which were not expected)
 */
static inline void *
atomic_ptr_cmpxchg(void **p, void *expectedv, void *newv)
{
    void *retv = expectedv;

    if (!__atomic_compare_exchange_n(p, &retv, newv, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        return (void *)retv;

    return (void *)newv;
}

/* The increment must complete before any subsequent load or store
 * (in program order across all cpus in the system) is performed.
 */
static inline int
atomic_inc_acq(atomic_t *v)
{
    return __atomic_add_fetch(&v->counter, 1, __ATOMIC_ACQUIRE);
}

/* All prior loads and stores (in program order across all cpus in
 * the system) must have completed before the decrement is performed.
 */
static inline int
atomic_dec_rel(atomic_t *v)
{
    return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_RELEASE);
}

/* All prior loads and stores (in program order across all cpus in
 * the system) must have completed before the store is performed.
 */
static inline void
atomic_set_rel(atomic_t *v, int n)
{
    __atomic_store_n(&v->counter, n, __ATOMIC_RELEASE);
}

/* The read must complete (in program order) before any subsequent
 * load or store is performed.
 */
static inline int
atomic_read_acq(const atomic_t *v)
{
    return __atomic_load_n(&v->counter, __ATOMIC_ACQUIRE);
}

static inline int
atomic_or_fetch_rel(atomic_t *v, int val)
{
    return __atomic_or_fetch(&v->counter, val, __ATOMIC_RELEASE);
}

static inline int
atomic_and_fetch_rel(atomic_t *v, int val)
{
    return __atomic_and_fetch(&v->counter, val, __ATOMIC_RELEASE);
}

static inline void *
atomic_ptr_exchange(void **p, void *val)
{
    return (void *)__atomic_exchange_n(p, val, __ATOMIC_RELAXED);
}

static inline void
atomic64_set_rel(atomic64_t *v, long i)
{
    __atomic_store_n(&v->counter, i, __ATOMIC_RELEASE);
}

/* Atomically reads the value of @v.
 *
 * The read must complete (in program order) before any subsequent
 * load or store is performed.
 */
static inline long
atomic64_read_acq(const atomic64_t *v)
{
    return __atomic_load_n(&v->counter, __ATOMIC_ACQUIRE);
}

/* Atomically return the current value of *v and then perform *v = *v + i.
 *
 * The fetch/add must complete before any subsequent load or store
 * (in program order across all cpus in the system) is performed.
 */
static inline long
atomic64_fetch_add_acq(long i, atomic64_t *v)
{
    return __atomic_fetch_add(&v->counter, i, __ATOMIC_ACQUIRE);
}

/* Atomically return the current value of *v and then perform *v = *v + i.
 *
 * All prior loads and stores (in program order across all cpus in
 * the system) must have completed before the fetch/add is performed.
 */
static inline long
atomic64_fetch_add_rel(long i, atomic64_t *v)
{
    return __atomic_fetch_add(&v->counter, i, __ATOMIC_RELEASE);
}

/* The increment must complete before any subsequent load or store
 * (in program order across all cpus in the system) is performed.
 */
static inline long
atomic64_inc_acq(atomic64_t *v)
{
    return __atomic_add_fetch(&v->counter, 1, __ATOMIC_ACQUIRE);
}

/* All prior loads and stores (in program order across all cpus in
 * the system) must have completed before the decrement is performed.
 */
static inline long
atomic64_inc_rel(atomic64_t *v)
{
    return __atomic_add_fetch(&v->counter, 1, __ATOMIC_RELEASE);
}

static inline long
atomic64_dec_rel(atomic64_t *v)
{
    return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_RELEASE);
}

#endif /* HSE_PLATFORM_ATOMIC_H */
