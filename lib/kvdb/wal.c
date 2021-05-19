/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <stdalign.h>
#include <sys/sysinfo.h>

#include <hse_util/platform.h>
#include <hse_util/vlb.h>
#include <hse_util/bonsai_tree.h>

#include <hse/hse.h>

#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/key_hash.h>
#include <hse_ikvdb/tuple.h>

#include "wal.h"

/* clang-format off */

/* Until we have some synchronization in place we need to make bufsz
 * large enough to accomodate several outstanding c0kvms buffers.
 */
#define WAL_BUFSZ_MAX       (16ul << 30)
#define WAL_NODE_MAX        (4)
#define WAL_BPN_MAX         (1)

#define WAL_BUFALLOCSZ_MAX \
    (ALIGN(WAL_BUFSZ_MAX + sizeof(struct wal_rec) + HSE_KVS_KLEN_MAX + HSE_KVS_VLEN_MAX, 2ul << 20))

struct wal {
    atomic64_t  w_offset HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    char       *w_buf    HSE_ALIGNED(SMP_CACHE_BYTES);
};

struct wal_rec {
    uint64_t    r_seqno;
    uint64_t    r_txid;
    int32_t     r_klen;
    uint64_t    r_vxlen;
    char        r_data[] HSE_ALIGNED(alignof(uint64_t));
};

/* clang-format on */

static struct wal walv[WAL_NODE_MAX * WAL_BPN_MAX];

merr_t
wal_put(
    struct ikvs *kvs,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *kt,
    struct kvs_vtuple *vt,
    u64 seqno)
{
    const size_t kvalign = alignof(uint64_t);
    uint cpuid, nodeid, coreid;
    struct wal_rec *rec;
    struct wal *wal;
    uint64_t offset, len;
    size_t klen, vlen;
    char *data;

    klen = kt->kt_len;
    vlen = kvs_vtuple_vlen(vt);
    len = sizeof(*rec) + ALIGN(klen, kvalign) + ALIGN(vlen, kvalign);

    hse_getcpu(&cpuid, &nodeid, &coreid);

    wal = walv;
    wal += (nodeid % WAL_NODE_MAX) * WAL_BPN_MAX;
    wal += (coreid % WAL_BPN_MAX);

    offset = atomic64_fetch_add(len, &wal->w_offset);
    offset %= WAL_BUFSZ_MAX;

    rec = (void *)(wal->w_buf + offset);

    rec->r_seqno = seqno;
    rec->r_txid = 0;
    rec->r_klen = klen;
    rec->r_vxlen = vt->vt_xlen;

    data = rec->r_data;
    memcpy(data, kt->kt_data, klen);
    kt->kt_data = data;
    kt->kt_flags = HSE_BTF_MANAGED;

    if (vlen > 0) {
        data = PTR_ALIGN(data + klen, kvalign);
        memcpy(data, vt->vt_data, vlen);
        vt->vt_data = data;
    }

    return 0;
}

merr_t
wal_init(void)
{
    uint i, j;

    for (i = 0; i < get_nprocs_conf(); ++i) {
        struct wal *wal;

        wal = walv + (hse_cpu2node(i) % WAL_NODE_MAX) * WAL_BPN_MAX;
        if (wal->w_buf)
            continue;

        for (j = 0; j < WAL_BPN_MAX; ++j, ++wal) {
            atomic64_set(&wal->w_offset, 0);

            wal->w_buf = vlb_alloc(WAL_BUFALLOCSZ_MAX);
            if (!wal->w_buf) {
                while (i-- > 0)
                    vlb_free(walv[i].w_buf, WAL_BUFALLOCSZ_MAX);

                return merr(ENOMEM);
            }
        }
    }

    return 0;
}

void
wal_fini(void)
{
    uint i;

    for (i = 0; i < WAL_NODE_MAX * WAL_BPN_MAX; ++i) {
        struct wal *wal = walv + i;

        vlb_free(wal->w_buf, WAL_BUFALLOCSZ_MAX);
    }
}

