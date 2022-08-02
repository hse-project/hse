/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CN_LTOK_H
#define HSE_CN_LTOK_H

#include <hse_util/atomic.h>
#include <hse_util/inttypes.h>
#include <hse_util/spinlock.h>

/* MTF_MOCK_DECL(ltok) */

enum ltok_token {
    ltok_spill,
    ltok_kcomp,
    ltok_kvcomp,
    ltok_split,
    ltok_join
};

struct ltok {
    spinlock_t  ltok_lock;
    atomic_int *ltok_signal;
    uint8_t     ltok_active_spills;
    uint8_t     ltok_active_kcomps;
    uint8_t     ltok_active_kvcomps;
    bool        ltok_active_join;
    bool        ltok_active_split;
    bool        ltok_reserved;
};

/**
 * ltok_init() - initialize leaf token structure
 */
/* MTF_MOCK */
void ltok_init(struct ltok *ltok);

/**
 * ltok_get() - request a token
 *
 * Returns:
 *   true  : request granted
 *   false : request denied.
 */
/* MTF_MOCK */
bool ltok_get(struct ltok *ltok, enum ltok_token token);

/**
 * ltok_put() - return a token
 *
 * Undefined behavior will result if caller puts a token type that is not
 * currently allocated.
 */
/* MTF_MOCK */
void ltok_put(struct ltok *ltok, enum ltok_token token);

/**
 * ltok_reserve() - request a reservation
 *
 * Make a reservation to ensure a token can be obtained without being starved by
 * other token requests.
 *
 * Reservations should only be used for split and join tokens.  There is no need
 * to use reservations for spill, kcompact or kvcompact because they can run
 * concurrently, and splits and joins are infrequent and extremely unlikely to
 * cause starvation on real systems.
 *
 * Notes:
 * - There can be at most one outstanding reservation.
 * - If signal is not NULL, it will be set when the reservation is ready, at
 *   which point the caller should use ltok_get_reserved() to convert the
 *   reservation to a token.
 *
 * Returns:
 *   true  : request granted
 *   false : request denied (eg: a reservation already exists)
 */
/* MTF_MOCK */
bool ltok_reserve(struct ltok *ltok, atomic_int *signal);

/**
 * ltok_get_reserved() - convert a reservation into a token
 *
 * Call after ltok_reserved() to get a token, and after the atomic passed to
 * ltok_reserved() becomes 1.  Should only be used with split and join tokens.
 */
/* MTF_MOCK */
bool ltok_get_reserved(struct ltok *ltok, enum ltok_token token);

/**
 * ltok_cancel_reservation() - cancel a reservation
 */
/* MTF_MOCK */
void ltok_cancel_reservation(struct ltok *ltok);

#if HSE_MOCKING
#include "ltok_ut.h"
#endif

#endif
