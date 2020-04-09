/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "c1_omf_internal.h"

#include <mpool/mpool.h>

merr_t
c1_journal_replay_impl(struct c1 *c1, struct c1_journal *jrnl, c1_journal_replay_cb *cb)
{
    struct c1_header hdr;
    merr_t           err;
    char *           hdromf;
    int              page_off, mdc_off;
    void *           rec;
    size_t           len;
    void *           buffer;
    bool             close;
    u32              cmd;
    u32              hdrlen;

    buffer = malloc(HSE_C1_JOURNAL_SIZE);
    if (ev(!buffer))
        return merr(ENOMEM);

    err = mpool_mdc_rewind(jrnl->c1j_mdc);
    if (ev(err)) {
        free(buffer);
        return err;
    }

    close = false;
    hdrlen = omf_c1_header_unpack_len();

    for (mdc_off = 0; !err;) {
        err = mpool_mdc_read(jrnl->c1j_mdc, buffer, HSE_C1_JOURNAL_SIZE, &len);
        if (ev(err))
            hse_elog(HSE_ERR "%s: failed: mpool_mdc_read @@e", err, __func__);

        if (len == 0 || ev(err))
            break;

        for (page_off = 0; page_off < len;) {

            hdromf = rec = (void *)(buffer + page_off);

            err = omf_c1_header_unpack(hdromf, &hdr);
            if (ev(err)) {
                free(buffer);
                return err;
            }

            cmd = hdr.c1h_type;

            err = cb(c1, cmd, rec, NULL);
            if (err == merr(EBADMSG)) {
                free(buffer);
                return 0;
            }

            if (ev(err))
                break;

            if (cmd == C1_TYPE_CLOSE) {
                err = 0;
                close = true;
                break;
            }

            page_off += hdrlen + hdr.c1h_len;
            mdc_off += hdrlen + hdr.c1h_len;
        }

        if (close)
            break;
    }

    free(buffer);
    if (ev(err))
        hse_elog(HSE_ERR "%s: journal replay  failed  @@e", err, __func__);

    return err;
}

merr_t
c1_journal_replay_default_cb(struct c1 *c1, u32 cmd, void *rec, void *rec2)
{
    merr_t err;

    switch (cmd) {
        case C1_TYPE_VERSION:
            err = c1_replay_version(c1, rec);
            break;

        case C1_TYPE_INFO:
            err = c1_replay_add_info(c1, rec);
            break;

        case C1_TYPE_DESC:
            err = c1_replay_add_desc(c1, rec);
            break;

        case C1_TYPE_INGEST:
            err = c1_replay_add_ingest(c1, rec);
            break;

        case C1_TYPE_RESET:
            err = c1_replay_add_reset(c1, rec);
            break;

        case C1_TYPE_CLOSE:
            c1_replay_add_close(c1, rec);
            err = 0;
            break;

        case C1_TYPE_COMPLETE:
            err = c1_replay_add_complete(c1, rec);
            break;

        default:
            err = merr(ev(EBADMSG));
            hse_elog(HSE_ERR "%s: journal replay unknown header @@e", err, __func__);
    }

    return err;
}
