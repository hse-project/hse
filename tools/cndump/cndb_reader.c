/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <hse/ikvdb/diag_kvdb.h>
#include <hse/mpool/mpool.h>

#include "cndb_reader.h"
#include "cndb_record.h"
#include "fatal.h"

static void
read_record(struct cndb_dump_reader *reader, struct cndb_rec *rec)
{
    merr_t err;
    size_t reclen;

    err = mpool_mdc_read(reader->mdc, rec->buf, rec->bufsz, &reclen);
    if (merr_errno(err) == EOVERFLOW) {
        cndb_rec_resize(rec, reclen);
        err = mpool_mdc_read(reader->mdc, rec->buf, rec->bufsz, &reclen);
    }

    if (err)
        fatal("mpool_mdc_read", err);

    if (reclen) {
        rec->type = omf_cnhdr_type(rec->buf);
        rec->len = omf_cnhdr_len(rec->buf);
        reader->eof = false;
    } else {
        reader->eof = true;
    }
}

void
cndb_iter_init(struct hse_kvdb *kvdb, struct cndb_dump_reader *r)
{
    merr_t err;
    struct cndb *cndb;

    err = diag_kvdb_get_cndb(kvdb, &cndb);
    if (err)
        fatal("diag_kvdb_get_cndb", err);

    r->mdc = cndb_mdc_get(cndb);
    r->eof = false;

    err = mpool_mdc_rewind(r->mdc);
    if (err)
        fatal("mpool_mdc_rewind", err);
}

bool
cndb_iter_next(struct cndb_dump_reader *r, struct cndb_rec *rec)
{
    read_record(r, rec);
    if (!r->eof)
        cndb_rec_parse(rec);
    return !r->eof;
}
