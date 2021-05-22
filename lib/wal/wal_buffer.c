/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <stdalign.h>
#include <sys/sysinfo.h>

#include <hse_util/platform.h>
#include <hse_util/page.h>
#include <hse_util/vlb.h>

#include "wal.h"
#include "wal_omf.h"
#include "wal_buffer.h"


/* Until we have some synchronization in place we need to make bufsz
 * large enough to accomodate several outstanding c0kvms buffers.
 */
#define WAL_BUFSZ_MAX       (32ul << 30)
#define WAL_NODE_MAX        (4)
#define WAL_BPN_MAX         (1)

#define WAL_BUFALLOCSZ_MAX \
    (ALIGN(WAL_BUFSZ_MAX + wal_rec_len() + HSE_KVS_KEY_LEN_MAX + HSE_KVS_VALUE_LEN_MAX, 2ul << 20))


struct wal_buffer {
    atomic64_t  w_offset HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    char       *w_buf    HSE_ALIGNED(SMP_CACHE_BYTES);
};

struct wal_buffer *
wal_buffer_create(void)
{
    struct wal_buffer *wbuf;
    uint i, j;
    size_t sz;

    sz = WAL_NODE_MAX * WAL_BPN_MAX * sizeof(*wbuf);
    wbuf = calloc(1, sz);
    if (!wbuf)
        return NULL;

    for (i = 0; i < get_nprocs_conf(); ++i) {
        struct wal_buffer *wb;

        wb = wbuf + (hse_cpu2node(i) % WAL_NODE_MAX) * WAL_BPN_MAX;
        if (wb->w_buf)
            continue;

        for (j = 0; j < WAL_BPN_MAX; ++j, ++wb) {
            atomic64_set(&wb->w_offset, 0);

            wb->w_buf = vlb_alloc(WAL_BUFALLOCSZ_MAX);
            if (!wb->w_buf) {
                while (i-- > 0)
                    vlb_free(wbuf[i].w_buf, WAL_BUFALLOCSZ_MAX);

                return NULL;
            }
        }
    }

    return wbuf;
}

void
wal_buffer_destroy(struct wal_buffer *wbuf)
{
    uint i;

    for (i = 0; i < WAL_NODE_MAX * WAL_BPN_MAX; ++i) {
        struct wal_buffer *wb = wbuf + i;

        vlb_free(wb->w_buf, WAL_BUFALLOCSZ_MAX);
    }
}

void *
wal_buffer_alloc(struct wal_buffer *wbuf, size_t len)
{
    struct wal_buffer *wb;
    uint cpuid, nodeid, coreid;
    uint64_t offset;

    hse_getcpu(&cpuid, &nodeid, &coreid);

    wb = wbuf;
    wb += (nodeid % WAL_NODE_MAX) * WAL_BPN_MAX;
    wb += (coreid % WAL_BPN_MAX);

    offset = atomic64_fetch_add(len, &wb->w_offset);
    offset %= WAL_BUFSZ_MAX;

    return wb->w_buf + offset;
}
