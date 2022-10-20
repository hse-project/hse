/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <hse_ikvdb/kvdb_modes.h>

MTF_BEGIN_UTEST_COLLECTION(kvdb_modes_test)

MTF_DEFINE_UTEST(kvdb_modes_test, modes)
{
    enum kvdb_open_mode mode;

    for (mode = KVDB_MODE_MIN; mode <= KVDB_MODE_MAX; mode++) {
        if (mode != KVDB_MODE_RDWR)
            ASSERT_EQ(false, kvdb_mode_allows_user_writes(mode));
        else
            ASSERT_EQ(true, kvdb_mode_allows_user_writes(mode));
    }

    for (mode = KVDB_MODE_MIN; mode <= KVDB_MODE_MAX; mode++) {
        if (mode <= KVDB_MODE_DIAG)
            ASSERT_EQ(false, kvdb_mode_allows_media_writes(mode));
        else
            ASSERT_EQ(true, kvdb_mode_allows_media_writes(mode));
    }

    for (mode = KVDB_MODE_MIN; mode <= KVDB_MODE_MAX; mode++) {
        if (mode != KVDB_MODE_DIAG)
            ASSERT_EQ(false, kvdb_mode_ignores_wal_replay(mode));
        else
            ASSERT_EQ(true, kvdb_mode_ignores_wal_replay(mode));
    }

    for (mode = KVDB_MODE_MIN; mode <= KVDB_MODE_MAX; mode++)
        ASSERT_EQ(false, kvdb_mode_is_invalid(mode));
    ASSERT_EQ(true, kvdb_mode_is_invalid(KVDB_MODE_MAX + 1));

    ASSERT_STREQ(KVDB_MODE_RDONLY_STR, kvdb_mode_to_string(KVDB_MODE_RDONLY));
    ASSERT_STREQ(KVDB_MODE_DIAG_STR, kvdb_mode_to_string(KVDB_MODE_DIAG));
    ASSERT_STREQ(KVDB_MODE_RDONLY_REPLAY_STR, kvdb_mode_to_string(KVDB_MODE_RDONLY_REPLAY));
    ASSERT_STREQ(KVDB_MODE_RDWR_STR, kvdb_mode_to_string(KVDB_MODE_RDWR));
    ASSERT_STREQ(KVDB_MODE_INVALID_STR, kvdb_mode_to_string(KVDB_MODE_MAX + 1));

    ASSERT_EQ(KVDB_MODE_RDONLY, kvdb_mode_string_to_value(KVDB_MODE_RDONLY_STR));
    ASSERT_EQ(KVDB_MODE_DIAG, kvdb_mode_string_to_value(KVDB_MODE_DIAG_STR));
    ASSERT_EQ(KVDB_MODE_RDONLY_REPLAY, kvdb_mode_string_to_value(KVDB_MODE_RDONLY_REPLAY_STR));
    ASSERT_EQ(KVDB_MODE_RDWR, kvdb_mode_string_to_value(KVDB_MODE_RDWR_STR));
    ASSERT_EQ(KVDB_MODE_MAX + 1, kvdb_mode_string_to_value(KVDB_MODE_INVALID_STR));
}

MTF_END_UTEST_COLLECTION(kvdb_modes_test)
