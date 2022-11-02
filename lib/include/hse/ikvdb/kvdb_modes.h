/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_MODES_H
#define HSE_KVDB_MODES_H

#include <stdbool.h>
#include <string.h>

#include <hse/util/assert.h>
#include <hse/util/compiler.h>

/**
 * KVDB open mode behavior:
 *
 * Mode             Dirty-WAL    Dirty-cNDB    Writes?    Compact?    Queries?    RO FS/Vol
 * ----------------------------------------------------------------------------------------
 * rdonly           EUCLEAN      Mem replay    No         No          Yes         Yes
 * diag             Ignore       Mem replay    No         No          Yes         Yes
 * rdonly_replay    Replay       Full replay   No         No          Yes         Error
 * rw (default)     Replay       Full replay   Yes        Yes         Yes         Error
 */
enum kvdb_open_mode {
    KVDB_MODE_RDONLY        = 0,
    KVDB_MODE_DIAG          = 1,
    KVDB_MODE_RDONLY_REPLAY = 2,
    KVDB_MODE_RDWR          = 3,
};

#define KVDB_MODE_MIN          KVDB_MODE_RDONLY
#define KVDB_MODE_MAX          KVDB_MODE_RDWR

#define KVDB_MODE_RDONLY_STR           "rdonly"
#define KVDB_MODE_DIAG_STR             "diag"
#define KVDB_MODE_RDONLY_REPLAY_STR    "rdonly_replay"
#define KVDB_MODE_RDWR_STR             "rdwr"
#define KVDB_MODE_INVALID_STR          "invalid"

#define KVDB_MODE_LIST_STR \
    KVDB_MODE_RDONLY_STR " " \
    KVDB_MODE_DIAG_STR " " \
    KVDB_MODE_RDONLY_REPLAY_STR " " \
    KVDB_MODE_RDWR_STR


static HSE_ALWAYS_INLINE bool
kvdb_mode_allows_user_writes(enum kvdb_open_mode mode)
{
    return mode == KVDB_MODE_RDWR;
}

static HSE_ALWAYS_INLINE bool
kvdb_mode_allows_media_writes(enum kvdb_open_mode mode)
{
    return mode == KVDB_MODE_RDONLY_REPLAY || mode == KVDB_MODE_RDWR;
}

static HSE_ALWAYS_INLINE bool
kvdb_mode_ignores_wal_replay(enum kvdb_open_mode mode)
{
    return mode == KVDB_MODE_DIAG;
}

static HSE_ALWAYS_INLINE bool
kvdb_mode_is_invalid(enum kvdb_open_mode mode)
{
    return mode > KVDB_MODE_MAX;
}

static HSE_ALWAYS_INLINE const char *
kvdb_mode_to_string(enum kvdb_open_mode mode)
{
    switch (mode) {
    case KVDB_MODE_RDONLY:
        return KVDB_MODE_RDONLY_STR;

    case KVDB_MODE_DIAG:
        return KVDB_MODE_DIAG_STR;

    case KVDB_MODE_RDONLY_REPLAY:
        return KVDB_MODE_RDONLY_REPLAY_STR;

    case KVDB_MODE_RDWR:
        return KVDB_MODE_RDWR_STR;

    default:
        return KVDB_MODE_INVALID_STR;
    }
}

static HSE_ALWAYS_INLINE enum kvdb_open_mode
kvdb_mode_string_to_value(const char *mode_str)
{
    INVARIANT(mode_str);

    if (!strcmp(mode_str, KVDB_MODE_RDONLY_STR))
        return KVDB_MODE_RDONLY;
    else if (!strcmp(mode_str, KVDB_MODE_DIAG_STR))
        return KVDB_MODE_DIAG;
    else if (!strcmp(mode_str, KVDB_MODE_RDONLY_REPLAY_STR))
        return KVDB_MODE_RDONLY_REPLAY;
    else if (!strcmp(mode_str, KVDB_MODE_RDWR_STR))
        return KVDB_MODE_RDWR;
    else
        return KVDB_MODE_MAX + 1;
}

#endif /* HSE_KVDB_MODES_H */
