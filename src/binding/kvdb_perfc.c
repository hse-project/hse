/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>

#include <hse_ikvdb/c0sk_perfc.h>

/*
 * The NE() macro string-izes the enum.
 * perfc_ctrseti_alloc() parses this string to get the type(!).
 */

struct perfc_name kvdb_perfc_op[] = {
    NE(PERFC_RA_KVDBOP_KVS_PUT, 1, "Count of kvs_put", "c_kvs_put(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_GET, 1, "Count of kvs_get", "c_kvs_get(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_DEL, 1, "Count of kvs_delete", "c_kvs_delete(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_PFXPROBE, 1, "Count of kvs_prefix_probe", "c_kvs_prefix_probe(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_PFX_DEL, 1, "Count of kvs_prefix_delete", "c_kvs_prefix_delete(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_SYNC, 1, "Count of kvdb_sync", "c_kvdb_sync(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_TXN_ALLOC, 1, "Count of kvdb_txn_alloc", "c_kvdb_txn_alloc(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_TXN_FREE, 1, "Count of kvdb_txn_free", "c_kvdb_txn_free(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_TXN_BEGIN, 1, "Count of kvdb_txn_begin", "c_kvdb_txn_begin(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_TXN_COMMIT, 1, "Count of kvdb_txn_commit", "c_kvdb_txn_commit(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_TXN_ABORT, 1, "Count of kvdb_txn_abort", "c_kvdb_txn_abort(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_CURSOR_CREATE,
       1,
       "Count of kvs_cursor_create",
       "c_kvs_cursor_create(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_CURSOR_UPDATE,
       1,
       "Count of kvs_cursor_update",
       "c_kvs_cursor_update(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_CURSOR_SEEK, 1, "Count of kvs_cursor_seek", "c_kvs_cursor_seek(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_CURSOR_READ, 1, "Count of kvs_cursor_read", "c_kvs_cursor_read(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_CURSOR_DESTROY,
       1,
       "Count of kvs_cursor_destroy",
       "c_kvs_cursor_destroy(/s)"),

    NE(PERFC_BA_KVDBOP_KVS_PUTB,     1, "kvs_put klen+vlen", "c_kvs_put_bytes"),
    NE(PERFC_BA_KVDBOP_KVS_GETB,     1, "kvs_get klen+vlen", "c_kvs_get_bytes"),
    NE(PERFC_BA_KVDBOP_KVS_DELB,     1, "kvs_del klen",      "c_kvs_del_bytes"),
    NE(PERFC_BA_KVDBOP_KVS_PFX_DELB, 1, "kvs_pfxdel klen",   "c_kvs_pfxdel_bytes"),

    NE(PERFC_RA_KVDBOP_KVDB_MAKE, 3, "Count of kvdb_make", "c_kvdb_make(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_OPEN, 3, "Count of kvdb_open", "c_kvdb_open(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_CLOSE, 3, "Count of kvdb_close", "c_kvdb_close(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_GET_NAMES, 3, "Count of kvdb_get_names", "c_kvdb_get_names(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_FREE_NAMES, 3, "Count of kvdb_free_names", "c_kvdb_free_names(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_KVS_COUNT, 3, "Count of kvdb_kvs_count", "c_kvdb_kvs_count(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_KVS_OPEN, 3, "Count of kvdb_kvs_open", "c_kvdb_kvs_open(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_KVS_CLOSE, 3, "Count of kvdb_kvs_close", "c_kvdb_kvs_close(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_KVS_MAKE, 3, "Count of kvdb_kvs_make", "c_kvdb_kvs_make(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_KVS_DROP, 3, "Count of kvdb_kvs_drop", "c_kvdb_kvs_drop(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_FLUSH, 3, "Count of kvdb_flush", "c_kvdb_flush(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_TXN_GET_STATE,
       3,
       "Count of kvdb_txn_get_state",
       "c_kvdb_txn_get_state(/s)"),
};

NE_CHECK(kvdb_perfc_op, PERFC_EN_KVDBOP, "kvdb_perfc_op table/enum mismatch");

/* Public kvdb interface latencies */
struct perfc_name kvdb_perfc_pkvdbl_op[] = {
    NE(PERFC_SL_PKVDBL_KVDB_SYNC, 1, "kvdb_sync latency", "kvdb_sync_lat"),

    NE(PERFC_LT_PKVDBL_KVDB_MAKE, 3, "kvdb_make latency", "kvdb_make_lat"),
    NE(PERFC_LT_PKVDBL_KVDB_DROP, 3, "kvdb_drop latency", "kvdb_drop_lat"),
    NE(PERFC_LT_PKVDBL_KVDB_OPEN, 3, "kvdb_open latency", "kvdb_open_lat"),
    NE(PERFC_LT_PKVDBL_KVDB_FLUSH, 3, "kvdb_flush latency", "kvdb_flush_lat"),
    NE(PERFC_LT_PKVDBL_KVDB_TXN_BEGIN, 3, "kvdb_txn_begin latency", "kvdb_txn_begin_lat"),
    NE(PERFC_LT_PKVDBL_KVDB_TXN_COMMIT, 3, "kvdb_txn_commit latency", "kvdb_txn_commit_lat"),
    NE(PERFC_LT_PKVDBL_KVDB_TXN_ABORT, 3, "kvdb_txn_abort latency", "kvdb_txn_abort_lat"),
    NE(PERFC_LT_PKVDBL_KVS_OPEN, 3, "kvs_open latency", "kvs_open_lat"),
};

NE_CHECK(kvdb_perfc_pkvdbl_op, PERFC_EN_PKVDBL, "kvdb_perfc_pkvdbl_op table/enum mismatch");

struct perfc_name c0_metrics_perfc[] = {
    NE(PERFC_BA_C0METRICS_KVMS_CNT, 2, "Instances of c0_kvmultiset", "c_kvmultiset"),
};

NE_CHECK(c0_metrics_perfc, PERFC_EN_C0METRICS, "c0_metrics_perfc table/enum mismatch");

struct perfc_name kvdb_metrics_perfc[] = {
    NE(PERFC_BA_KVDBMETRICS_CURCNT, 2, "Current kvdb cursor count", "curcnt"),

    NE(PERFC_BA_KVDBMETRICS_SEQNO, 3, "Current kvdb seqno", "c_seqno"),
    NE(PERFC_BA_KVDBMETRICS_CURHORIZON, 3, "Cursor kvdb horizon", "cur_horizon"),
    NE(PERFC_BA_KVDBMETRICS_HORIZON, 3, "Current kvdb horizon", "horizon"),
    NE(PERFC_DI_KVDBMETRICS_THROTTLE, 3, "Put/get/del throttle (ns)", "api_throttle", 10),
};

NE_CHECK(kvdb_metrics_perfc, PERFC_EN_KVDBMETRICS, "kvdb_metrics_perfc table/enum mismatch");

struct perfc_name csched_sp3_perfc[] = {
    NE(PERFC_BA_SP3_SAMP, 2, "spaceamp", "c_samp"),
    NE(PERFC_BA_SP3_REDUCE, 2, "reduce flag", "c_reduce"),

    NE(PERFC_BA_SP3_LGOOD_CURR, 3, "currrent leaf used size ", "c_lgood"),
    NE(PERFC_BA_SP3_LGOOD_TARG, 3, "target leaf used size ", "t_lgood"),
    NE(PERFC_BA_SP3_LSIZE_CURR, 3, "currrent leaf size ", "c_lsize"),
    NE(PERFC_BA_SP3_LSIZE_TARG, 3, "target leaf size ", "t_lsize"),
    NE(PERFC_BA_SP3_RSIZE_CURR, 3, "currrent non-leaf size ", "c_rsize"),
    NE(PERFC_BA_SP3_RSIZE_TARG, 3, "target non-leaf size ", "t_rsize"),
};
NE_CHECK(csched_sp3_perfc, PERFC_EN_SP3, "csched_sp3_perfc table/enum mismatch");

void
kvdb_perfc_init(void)
{
    struct perfc_ivl * ivl;
    struct perfc_name *pcn;
    const u64          usecs = 1000;
    const u64          msecs = 1000000;

    u64 boundv[] = {
        /* 10, 100, .. 800 ns */
        10,          100,         200,         400,         600,         800,

        1 * usecs,   2 * usecs,   4 * usecs,   6 * usecs,   8 * usecs,

        10 * usecs,  20 * usecs,  40 * usecs,  60 * usecs,  80 * usecs,

        100 * usecs, 200 * usecs, 400 * usecs, 600 * usecs, 800 * usecs,

        1 * msecs,   2 * msecs,   4 * msecs,   6 * msecs,   8 * msecs,

        10 * msecs,  50 * msecs,
    };

    pcn = &kvdb_metrics_perfc[PERFC_DI_KVDBMETRICS_THROTTLE];
    if (!perfc_ivl_create(NELEM(boundv), boundv, &ivl)) {
        pcn->pcn_ivl = ivl;
        pcn->pcn_samplepct = 3;
    }
}

void
kvdb_perfc_fini(void)
{
    struct perfc_name *pcn;

    pcn = &kvdb_metrics_perfc[PERFC_DI_KVDBMETRICS_THROTTLE];
    perfc_ivl_destroy(pcn->pcn_ivl);
    pcn->pcn_ivl = 0;
}
