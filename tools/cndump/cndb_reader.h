/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#ifndef CNDUMP_CNDB_READER_H
#define CNDUMP_CNDB_READER_H

#include <stdbool.h>
#include <stdint.h>

struct hse_kvdb;
struct mpool_mdc;
struct cndb_rec;

struct cndb_dump_reader {
    struct mpool_mdc *mdc;
    bool eof;
};

void
cndb_iter_init(struct hse_kvdb *kvdb, struct cndb_dump_reader *r);

bool
cndb_iter_next(struct cndb_dump_reader *r, struct cndb_rec *record);

void
cndb_iter_fini(struct cndb_dump_reader *r);

#endif
