/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_ltok

#include "ltok.h"

#if HSE_MOCKING
#include "ltok_ut_impl.i"
#endif

void
ltok_init(struct ltok *ltok)
{
    memset(ltok, 0, sizeof(*ltok));
    spin_lock_init(&ltok->ltok_lock);
}

static inline
unsigned
shared_users(struct ltok *ltok)
{
    return ltok->ltok_active_spills + ltok->ltok_active_kcomps + ltok->ltok_active_kvcomps;
}

static inline
bool
is_idle(struct ltok *ltok)
{
    return shared_users(ltok) == 0 && !ltok->ltok_active_join && !ltok->ltok_active_split;
}

static inline
bool
allow_shared(struct ltok *ltok, uint8_t *counter)
{
    if (ltok->ltok_active_join || ltok->ltok_active_split || ltok->ltok_reserved)
        return false;

    if (*counter == UINT8_MAX)
        return false;

    *counter += 1;
    return true;
}

static inline
bool
allow_exclusive(struct ltok *ltok, bool *granted)
{
    if (is_idle(ltok) && !ltok->ltok_reserved) {
        *granted = true;
        return true;
    }

    return false;
}

bool
ltok_get(struct ltok *ltok, enum ltok_token token)
{
    bool granted = false;

    spin_lock(&ltok->ltok_lock);

    switch (token) {

    case ltok_spill:
        granted = allow_shared(ltok, &ltok->ltok_active_spills);
        break;

    case ltok_kcomp:
        granted = allow_shared(ltok, &ltok->ltok_active_kcomps);
        break;

    case ltok_kvcomp:
        granted = allow_shared(ltok, &ltok->ltok_active_kvcomps);
        break;

    case ltok_split:
        granted = allow_exclusive(ltok, &ltok->ltok_active_split);
        break;

    case ltok_join:
        granted = allow_exclusive(ltok, &ltok->ltok_active_join);
        break;
    }

    spin_unlock(&ltok->ltok_lock);

    return granted;
}

void
ltok_put(struct ltok *ltok, enum ltok_token token)
{
    spin_lock(&ltok->ltok_lock);

    switch (token) {

    case ltok_spill:
        assert(ltok->ltok_active_spills > 0);
        ltok->ltok_active_spills -= 1;
        break;

    case ltok_kcomp:
        assert(ltok->ltok_active_kcomps > 0);
        ltok->ltok_active_kcomps -= 1;
        break;

    case ltok_kvcomp:
        assert(ltok->ltok_active_kvcomps > 0);
        ltok->ltok_active_kvcomps -= 1;
        break;

    case ltok_split:
        assert(ltok->ltok_active_split);
        ltok->ltok_active_split = false;
        break;

    case ltok_join:
        assert(ltok->ltok_active_join);
        ltok->ltok_active_join = false;
        break;
    }

    /* Notify reservation if exclusive token is available */
    if (ltok->ltok_reserved && ltok->ltok_signal && is_idle(ltok)) {
        atomic_set(ltok->ltok_signal, 1);
    }

    spin_unlock(&ltok->ltok_lock);
}

bool
ltok_reserve(struct ltok *ltok, atomic_int *signal)
{
    bool granted = false;

    spin_lock(&ltok->ltok_lock);

    if (!ltok->ltok_reserved) {
        granted = true;
        ltok->ltok_reserved = true;
        ltok->ltok_signal = signal;
        if (signal && is_idle(ltok))
            atomic_set(signal, 1);
    }

    spin_unlock(&ltok->ltok_lock);

    return granted;
}

void
ltok_cancel_reservation(struct ltok *ltok)
{
    spin_lock(&ltok->ltok_lock);

    ltok->ltok_reserved = false;
    ltok->ltok_signal = NULL;

    spin_unlock(&ltok->ltok_lock);
}

bool
ltok_get_reserved(struct ltok *ltok, enum ltok_token token)
{
    bool granted = false;

    spin_lock(&ltok->ltok_lock);

    if (is_idle(ltok) && ltok->ltok_reserved) {

        granted = true;
        ltok->ltok_reserved = false;
        ltok->ltok_signal = NULL;

        switch (token) {
        case ltok_spill:
            ltok->ltok_active_spills += 1;
            break;
        case ltok_kcomp:
            ltok->ltok_active_kcomps += 1;
            break;
        case ltok_kvcomp:
            ltok->ltok_active_kvcomps += 1;
            break;
        case ltok_split:
            ltok->ltok_active_split = true;
            break;
        case ltok_join:
            ltok->ltok_active_join = true;
            break;
        }
    }

    spin_unlock(&ltok->ltok_lock);

    return granted;
}
