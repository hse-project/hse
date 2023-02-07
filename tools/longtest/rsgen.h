/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef RSGEN_H
#define RSGEN_H

#include <stdbool.h>
#include <stdint.h>

/*
 * The approach used here to generate large random strings doesn't work too
 * well with extremely large values, so we limit the max value length to avoid
 * disappointing unsuspecting users.
 */
#define RS_MAX_VALUE_LEN  (1024*1024)

struct rsgen {
    uint8_t *rs_buf;
    uint64_t rs_max_iter;
    uint64_t rs_max_id;
    uint32_t rs_min_len;
    uint32_t rs_max_len;
    uint32_t rs_seed;
    uint32_t rs_hidden_iter_bytes;
    uint32_t rs_hidden_id_bytes;
    uint32_t rs_prefix_tid_bytes;
    bool     rs_tags;
    char     rs_errmsg[256];
};

int
rsgen_init(
    struct rsgen   *rs,
    uint64_t        max_id,
    uint64_t        max_iter,
    bool            tags,
    uint32_t        min_len,
    uint32_t        max_len,
    uint32_t        nthreads,
    uint32_t        seed);

void
rsgen_str(
    struct rsgen   *rs,
    uint16_t        tid,
    uint64_t        id,
    uint64_t        iter,
    uint8_t         tag,
    void           *val,
    uint32_t       *len);

void
rsgen_set_tid(
    struct rsgen  *rs,
    void          *buf,
    uint16_t            tid);

uint16_t
rsgen_decode(
    void         *str,
    int           len,
    uint64_t     *id,
    uint64_t     *iter,
    uint8_t      *tag);

void
rsgen_fini(
    struct rsgen   *rs);


#endif
