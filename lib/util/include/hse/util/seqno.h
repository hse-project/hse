/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_SEQNO_H
#define HSE_PLATFORM_SEQNO_H

#include <hse/util/assert.h>
#include <hse/util/inttypes.h>

/* A sequence number reference is an entity that is resolvable to one of three
 * values:
 *
 *   - HSE_SQNREF_UNDEFINED
 *   - HSE_SQNREF_ABORTED
 *   - An encoded value that is a KVDB sequence number
 *
 * It is represented as a 64-bit quantity (i.e., uintptr_t) that is either a
 * value or a pointer to a value. The 64-bit quantity's low-order bit is
 * either 0 or 1.
 *
 * If it is a 1, then the quantity is contains a valid ordinal value that can
 * be obtained by the use of HSE_SEQNO_TO_ORDNL(). If instead it is a 0, then
 * one of three things is possible:
 *
 *     - It has the special value HSE_SEQNO_UNDEFINED meaning that the
 *       sequence number is not yet defined to have any value.
 *     - It has the special value HSE_SEQNO_ABORTED meaning that the
 *       sequence number will never have any value.
 *     - It is a pointer to the sequence number
 */

#define HSE_SQNREF_UNDEFINED (0xfffffffffffffffe)
#define HSE_SQNREF_ABORTED (0xfffffffffffffffc)
#define HSE_SQNREF_INVALID (0xfffffffffffffffa)
#define HSE_SQNREF_SINGLE (0xfffffffffffffff8)
#define HSE_SQNREF_MASK (0xfffffffffffffff0)

#define HSE_SQNREF_UNDEF_P(snr) ((uintptr_t)(snr) == HSE_SQNREF_UNDEFINED)
#define HSE_SQNREF_ABORTED_P(snr) ((uintptr_t)(snr) == HSE_SQNREF_ABORTED)
#define HSE_SQNREF_INVALID_P(snr) ((uintptr_t)(snr) == HSE_SQNREF_INVALID)
#define HSE_SQNREF_SINGLE_P(snr) ((uintptr_t)(snr) == HSE_SQNREF_SINGLE)
#define HSE_SQNREF_ORDNL_P(snr) (((uintptr_t)(snr)&0x1UL) == 1)
#define HSE_SQNREF_INDIRECT_P(snr) (((uintptr_t)(snr)&0x1UL) == 0)

#define HSE_SQNREF_TO_ORDNL(snr) \
    (HSE_SQNREF_ORDNL_P(snr) ? (((uintptr_t)(snr)) >> 1) : ((*(uintptr_t *)(snr)) >> 1))
#define HSE_ORDNL_TO_SQNREF(ord) ((uintptr_t)(((ord) << 1) | 0x1UL))
#define HSE_SQNREF_TO_SQNREF(snr) (*(uintptr_t *)(snr))
#define HSE_REF_TO_SQNREF(ref) ((uintptr_t)(ref))

enum hse_seqno_state {
    HSE_SQNREF_STATE_INVALID = 1,
    HSE_SQNREF_STATE_UNDEFINED = 2,
    HSE_SQNREF_STATE_DEFINED = 3,
    HSE_SQNREF_STATE_ABORTED = 4,
    HSE_SQNREF_STATE_SINGLE = 5,
};

static inline enum hse_seqno_state
seqnoref_to_seqno(uintptr_t seqnoref, u64 *seqno)
{
    uintptr_t oseqnoref = 0;

restart:
    if (HSE_SQNREF_ORDNL_P(seqnoref)) {
        if (seqno)
            *seqno = HSE_SQNREF_TO_ORDNL(seqnoref);
        return HSE_SQNREF_STATE_DEFINED;
    } else if ((seqnoref & HSE_SQNREF_MASK) == HSE_SQNREF_MASK) {
        if (HSE_SQNREF_SINGLE_P(seqnoref))
            return HSE_SQNREF_STATE_SINGLE;
        if (HSE_SQNREF_INVALID_P(seqnoref))
            return HSE_SQNREF_STATE_INVALID;
        if (HSE_SQNREF_UNDEF_P(seqnoref))
            return HSE_SQNREF_STATE_UNDEFINED;

        assert(HSE_SQNREF_ABORTED_P(seqnoref));
        return HSE_SQNREF_STATE_ABORTED;
    } else if (oseqnoref == 0) {
        oseqnoref = seqnoref;
        seqnoref = HSE_SQNREF_TO_SQNREF(seqnoref);
        goto restart;
    }

    assert(oseqnoref == 0);

    return HSE_SQNREF_STATE_INVALID;
}

/**
 * seqnoref_ext_diff() - compute difference of two ordered ordinal values
 * @seq0:       ordinal seqno (the minuend)
 * @sqnref1:    valid seqnoref (the subtrahend)
 *
 * sqnref1 need not resolve to an ordinal value.
 *
 * Return:  The difference between seq0 and seq1 if sqnref1 resolves
 * to an ordinal value and (seq0 >= seq1).  Otherwise ULONG_MAX.
 */
static inline u64
seqnoref_ext_diff(u64 seq0, uintptr_t sqnref1)
{
    u64 seq1;

    if (seqnoref_to_seqno(sqnref1, &seq1) != HSE_SQNREF_STATE_DEFINED)
        return ULONG_MAX;

    return seq0 < seq1 ? ULONG_MAX : seq0 - seq1;
}

/**
 * seqnoref_diff() - compute difference of two ordered ordinal values
 * @sqnref0:    valid seqnoref (the minuend)
 * @sqnref1:    valid seqnoref (the subtrahend)
 *
 * Neither sqnref0 nor sqnref1 need resolve to an ordinal value.
 *
 * Return:  The difference between seq0 and seq1 if both sqnref0 and sqnref1
 * resolve to ordinal values and (seq0 >= seq1).  Otherwise ULONG_MAX.
 */
static inline u64
seqnoref_diff(uintptr_t sqnref0, uintptr_t sqnref1)
{
    u64 seq0;

    if (seqnoref_to_seqno(sqnref0, &seq0) != HSE_SQNREF_STATE_DEFINED)
        return ULONG_MAX;

    return seqnoref_ext_diff(seq0, sqnref1);
}

static inline bool
seqnoref_gt(uintptr_t sqnref0, uintptr_t sqnref1)
{
    u64                     seq0 = 0, seq1 = 0;
    enum hse_seqno_state    state0;

    state0 = seqnoref_to_seqno(sqnref0, &seq0);

    /*
     * Active transaction elements are always at the front and "greater"
     * than any other element on the list.
     */
    if (state0 == HSE_SQNREF_STATE_UNDEFINED)
        return true;

    /*
     * [HSE_REVISIT]
     * This needs to be updated when the transactional/non-transactional
     * model changes.
     * If the list contains elements inserted by transactions alone or by
     * non-transactions alone, is there a need to search for its position?
     * Can it be inserted at the head of the list?
     *
     * For now, continue comparing if there are elements on the list without a
     * valid seqno (active). Active/aborted elements may be interspersed with
     * elements with valid seqnos.
     */
    if (state0 != HSE_SQNREF_STATE_DEFINED ||
        seqnoref_to_seqno(sqnref1, &seq1) != HSE_SQNREF_STATE_DEFINED)
        return false;

    return seq0 > seq1;
}

static inline bool
seqnoref_ge(uintptr_t sqnref0, uintptr_t sqnref1)
{
    u64 seq0 = 0, seq1 = 0;

    if (seqnoref_to_seqno(sqnref0, &seq0) != HSE_SQNREF_STATE_DEFINED) {
        assert(0);
        return false;
    }

    if (seqnoref_to_seqno(sqnref1, &seq1) != HSE_SQNREF_STATE_DEFINED)
        return true;

    return seq0 >= seq1;
}

#endif
