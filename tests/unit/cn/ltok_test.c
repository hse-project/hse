/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mock/api.h>

#include <cn/ltok.h>

MTF_BEGIN_UTEST_COLLECTION(ltok_test);


const enum ltok_token all_types[] = {
    ltok_spill,
    ltok_kcomp,
    ltok_kvcomp,
    ltok_split,
    ltok_join
};

const enum ltok_token shared_types[] = {
    ltok_spill,
    ltok_kcomp,
    ltok_kvcomp
};

const enum ltok_token exclusive_types[] = {
    ltok_split,
    ltok_join
};

MTF_DEFINE_UTEST(ltok_test, t_ltok_token_exclusive)
{
    struct ltok ltok;
    bool granted;

    ltok_init(&ltok);

    for (int i = 0; i < NELEM(exclusive_types); i++) {
        enum ltok_token token1 = exclusive_types[i];

        /* Get any exclusive token type */
        granted = ltok_get(&ltok, token1);
        ASSERT_TRUE(granted);

        /* Should not be able to get any other token types */
        for (int j = 0; j < NELEM(all_types); j++) {
            enum ltok_token token2 = all_types[j];

            granted = ltok_get(&ltok, token2);
            ASSERT_FALSE(granted);
        }

        ltok_put(&ltok, token1);
    }
}

MTF_DEFINE_UTEST(ltok_test, t_ltok_token_shared)
{
    struct ltok ltok;
    bool granted;

    ltok_init(&ltok);

    for (int i = 0; i < NELEM(shared_types); i++) {
        enum ltok_token token1 = shared_types[i];

        /* Get any shared token type */
        granted = ltok_get(&ltok, token1);
        ASSERT_TRUE(granted);

        /* Additional gets for shared types should succeed */
        for (int j = 0; j < NELEM(shared_types); j++) {
            enum ltok_token token2 = shared_types[j];

            granted = ltok_get(&ltok, token2);
            ASSERT_TRUE(granted);
        }

        /* Put back the additional shared tokens */
        for (int j = 0; j < NELEM(shared_types); j++) {
            enum ltok_token token2 = shared_types[j];

            ltok_put(&ltok, token2);
        }

        /* Gets for exclusive token types should fail bc token1 is still held */
        for (int j = 0; j < NELEM(exclusive_types); j++) {
            enum ltok_token token2 = exclusive_types[j];

            granted = ltok_get(&ltok, token2);
            ASSERT_FALSE(granted);
        }

        ltok_put(&ltok, token1);
    }
}

MTF_DEFINE_UTEST(ltok_test, t_ltok_get_no_contention)
{
    struct ltok ltok;
    bool reserved, granted;
    atomic_int signal;
    int available;

    ltok_init(&ltok);

    /* Test with and with out signal */
    for (int use_signal = 0; use_signal <= 1; use_signal++) {

        for (int i = 0; i < NELEM(all_types); i++) {
            enum ltok_token token1 = all_types[i];

            /* Make reservation for any token type */
            if (use_signal)
                atomic_set(&signal, 0);
            reserved = ltok_reserve(&ltok, use_signal ? &signal : NULL);
            ASSERT_TRUE(reserved);

            /* Verify signal is 1 (bc there's no contention) */
            if (use_signal) {
                available = atomic_read(&signal);
                ASSERT_EQ(available, 1);
            }

            /* Convert reservation to token */
            granted = ltok_get_reserved(&ltok, token1);
            ASSERT_TRUE(granted);

            /* Put back the reserved token */
            ltok_put(&ltok, token1);
        }
    }
}

MTF_DEFINE_UTEST(ltok_test, t_ltok_get_with_contention)
{
    struct ltok ltok;
    bool reserved, granted;
    atomic_int signal;
    int available;

    ltok_init(&ltok);

    /* Test with and with out signal */
    for (int use_signal = 0; use_signal <= 1; use_signal++) {

        for (int i = 0; i < NELEM(all_types); i++) {
            enum ltok_token token1 = all_types[i];

            /* Get any token type */
            granted = ltok_get(&ltok, token1);
            ASSERT_TRUE(granted);

            /* Make reservation */
            if (use_signal)
                atomic_set(&signal, 0);
            reserved = ltok_reserve(&ltok, use_signal ? &signal : NULL);
            ASSERT_TRUE(reserved);

            /* Additional reservations should fail (can only have one
             * reservation at a time)
             */
            reserved = ltok_reserve(&ltok,  NULL);
            ASSERT_FALSE(reserved);

            /* Verify signal has not been set (bc token1 is still held) */
            if (use_signal) {
                available = atomic_read(&signal);
                ASSERT_EQ(available, 0);
            }

            /* Verify get and get_reserved fo all token types fail (cannot issue
             * tokens since reservation is pending).
             */
            for (int j = 0; j < NELEM(all_types); j++) {
                enum ltok_token token2 = all_types[j];

                granted = ltok_get(&ltok, token2);
                ASSERT_FALSE(granted);

                granted = ltok_get_reserved(&ltok, token2);
                ASSERT_FALSE(granted);
            }

            /* Put the original token, clearing the way for the reservation. */
            ltok_put(&ltok, token1);

            /* Non reserved gets should fail */
            for (int j = 0; j < NELEM(all_types); j++) {
                enum ltok_token token2 = all_types[j];

                granted = ltok_get(&ltok, token2);
                ASSERT_FALSE(granted);
            }

            /* Reserved get should succeed */
            granted = ltok_get_reserved(&ltok, ltok_split);
            ASSERT_TRUE(granted);

            /* Put the reserved token */
            ltok_put(&ltok, ltok_split);
        }
    }
}

MTF_END_UTEST_COLLECTION(ltok_test)
