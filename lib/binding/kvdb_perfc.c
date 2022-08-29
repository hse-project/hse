/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>

#include <hse/util/platform.h>
#include <hse/util/perfc.h>

#include <hse/ikvdb/hse_gparams.h>
#include <hse/kvdb_perfc.h>

/* clang-format off */

struct perfc_name kvdb_perfc_op[] _dt_section = {
    NE(PERFC_RA_KVDBOP_KVS_GET,         1, "kvs_get rate",            "r_kvs_get(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_GETB,        1, "kvs_get klen+vlen",       "r_kvs_get_bytes(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_PUT,         1, "kvs_put rate",            "r_kvs_put(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_PUTB,        1, "kvs_put klen+vlen",       "r_kvs_put_bytes(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_DEL,         1, "kvs_delete rate",         "r_kvs_delete(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_DELB,        1, "kvs_del klen",            "r_kvs_del_bytes(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_PFX_DELB,    1, "kvs_pfxdel klen",         "r_kvs_pfxdel_bytes(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_PFXPROBE,    1, "kvs_prefix_probe rate",   "r_kvs_prefix_probe(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_PFX_DEL,     1, "kvs_prefix_delete rate",  "r_kvs_prefix_delete(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_SYNC,       1, "kvdb_sync rate",          "r_kvdb_sync(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_TXN_ALLOC,  1, "kvdb_txn_alloc rate",     "r_kvdb_txn_alloc(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_TXN_FREE,   1, "kvdb_txn_free rate",      "r_kvdb_txn_free(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_TXN_BEGIN,  1, "kvdb_txn_begin rate",     "r_kvdb_txn_begin(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_TXN_COMMIT, 1, "kvdb_txn_commit rate",    "r_kvdb_txn_commit(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_TXN_ABORT,  1, "kvdb_txn_abort rate",     "r_kvdb_txn_abort(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_CURSOR_CREATE,
       1, "kvs_cursor_create rate", "r_kvs_cursor_create(/s)"),

    NE(PERFC_RA_KVDBOP_KVS_CURSOR_UPDATE,
       1, "Count of kvs_cursor_update", "c_kvs_cursor_update(/s)"),

    NE(PERFC_RA_KVDBOP_KVS_CURSOR_SEEK, 1, "kvs_cursor_seek rate",    "r_kvs_cursor_seek(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_CURSOR_READ, 1, "kvs_cursor_read rate",    "r_kvs_cursor_read(/s)"),
    NE(PERFC_RA_KVDBOP_KVS_CURSOR_DESTROY,
       1, "kvs_cursor_destroy rate", "r_kvs_cursor_destroy(/s)"),

    NE(PERFC_RA_KVDBOP_KVDB_CREATE,       3, "kvdb_make rate",          "r_kvdb_make(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_OPEN,       3, "kvdb_open rate",          "r_kvdb_open(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_CLOSE,      3, "kvdb_close rate",         "r_kvdb_close(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_KVS_NAMES_GET,  3, "kvdb_get_names rate",     "r_kvdb_get_names(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_KVS_NAMES_FREE, 3, "kvdb_free_names rate",    "r_kvdb_free_names(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_KVS_OPEN,   3, "kvdb_kvs_open rate",      "r_kvdb_kvs_open(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_KVS_CLOSE,  3, "kvdb_kvs_close rate",     "r_kvdb_kvs_close(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_KVS_CREATE,   3, "kvdb_kvs_make rate",      "r_kvdb_kvs_make(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_KVS_DROP,   3, "kvdb_kvs_drop rate",      "r_kvdb_kvs_drop(/s)"),
    NE(PERFC_RA_KVDBOP_KVDB_TXN_GET_STATE,
       3, "kvdb_txn_get_state rate", "r_kvdb_txn_get_state(/s)"),
};

NE_CHECK(kvdb_perfc_op, PERFC_EN_KVDBOP, "kvdb_perfc_op table/enum mismatch");

/* Public kvdb interface latencies */
struct perfc_name kvdb_perfc_pkvdbl_op[] _dt_section = {
    NE(PERFC_SL_PKVDBL_KVDB_SYNC,       1, "kvdb_sync latency",       "l_kvdb_sync"),
    NE(PERFC_LT_PKVDBL_KVDB_CREATE,     3, "kvdb_create latency",     "l_kvdb_create"),
    NE(PERFC_LT_PKVDBL_KVDB_DROP,       3, "kvdb_drop latency",       "l_kvdb_drop"),
    NE(PERFC_LT_PKVDBL_KVDB_OPEN,       3, "kvdb_open latency",       "l_kvdb_open"),
    NE(PERFC_LT_PKVDBL_KVDB_TXN_BEGIN,  3, "kvdb_txn_begin latency",  "l_kvdb_txn_begin"),
    NE(PERFC_LT_PKVDBL_KVDB_TXN_COMMIT, 3, "kvdb_txn_commit latency", "l_kvdb_txn_commit"),
    NE(PERFC_LT_PKVDBL_KVDB_TXN_ABORT,  3, "kvdb_txn_abort latency",  "l_kvdb_txn_abort"),
    NE(PERFC_LT_PKVDBL_KVS_OPEN,        3, "kvs_open latency",        "l_kvs_open"),
};

NE_CHECK(kvdb_perfc_pkvdbl_op, PERFC_EN_PKVDBL, "kvdb_perfc_pkvdbl_op table/enum mismatch");

struct perfc_name c0_metrics_perfc[] _dt_section = {
    NE(PERFC_BA_C0METRICS_KVMS_CNT,     2, "c0_kvmultiset count",     "c_kvmultiset"),
};

NE_CHECK(c0_metrics_perfc, PERFC_EN_C0METRICS, "c0_metrics_perfc table/enum mismatch");

struct perfc_name kvdb_metrics_perfc[] _dt_section = {
    NE(PERFC_BA_KVDBMETRICS_CURCNT,     0, "Active cursor count",         "c_cur_active"),
    NE(PERFC_RA_KVDBMETRICS_CURRETIRED, 0, "Cached cursor retired rate",  "r_cur_retired(/s)"),
    NE(PERFC_RA_KVDBMETRICS_CUREVICTED, 0, "Cached cursor eviction rate", "r_cur_evicted(/s)"),

    NE(PERFC_BA_KVDBMETRICS_SEQNO,      3, "Current kvdb seqno",          "c_seqno"),
    NE(PERFC_BA_KVDBMETRICS_CURHORIZON, 3, "Cursor kvdb horizon",         "cur_horizon"),
    NE(PERFC_BA_KVDBMETRICS_HORIZON,    3, "Current kvdb horizon",        "horizon"),
    NE(PERFC_DI_KVDBMETRICS_THROTTLE,   3, "Put/get/del throttle (ns)",   "d_api_throttle", 10),
};

NE_CHECK(kvdb_metrics_perfc, PERFC_EN_KVDBMETRICS, "kvdb_metrics_perfc table/enum mismatch");

struct perfc_set kvdb_pkvdbl_pc HSE_READ_MOSTLY;
struct perfc_set kvdb_pc        HSE_READ_MOSTLY;

struct perfc_set kvdb_metrics_pc HSE_READ_MOSTLY;
struct perfc_set c0_metrics_pc   HSE_READ_MOSTLY;

void
kvdb_perfc_init(void)
{
    uint prio = hse_gparams.gp_perfc_level;
    struct perfc_ivl * ivl;
    struct perfc_name *pcn;
    const uint64_t     usecs = 1000;
    const uint64_t     msecs = 1000000;

    uint64_t boundv[] = {
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

    perfc_alloc(kvdb_perfc_op, "global", "set", prio, &kvdb_pc);
    perfc_alloc(kvdb_perfc_pkvdbl_op, "global", "set", prio, &kvdb_pkvdbl_pc);
    perfc_alloc(c0_metrics_perfc, "global", "set", prio, &c0_metrics_pc);
    perfc_alloc(kvdb_metrics_perfc, "global", "set", prio, &kvdb_metrics_pc);
}

void
kvdb_perfc_fini(void)
{
    struct perfc_name *pcn;

    perfc_free(&kvdb_metrics_pc);
    perfc_free(&c0_metrics_pc);
    perfc_free(&kvdb_pkvdbl_pc);
    perfc_free(&kvdb_pc);

    pcn = &kvdb_metrics_perfc[PERFC_DI_KVDBMETRICS_THROTTLE];
    perfc_ivl_destroy(pcn->pcn_ivl);
    pcn->pcn_ivl = 0;
}

/* clang-format on */
