/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_RPARAMS_H
#define HSE_KVS_RPARAMS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <cjson/cJSON.h>

#include <hse_ikvdb/mclass_policy.h>
#include <hse_ikvdb/vcomp_params.h>

/*
 * Steps to add a new KVS parameter:
 * 1. Add a new struct element to struct kvs_params.
 * 2. Add a new entry to pspecs[].
 */

/**
 * struct kvs_rparams  - kvs runtime parameters
 *
 * The following tunable parameters can have a major impact on the way KVDB
 * operates.  Test thoroughly after any modifications.
 *
 * To improve cacheline utilization, group frequently accessed fields
 * towards the beginning of this structure, and rarely accesssed
 * fields towards the end.
 */
struct kvs_rparams {
    uint64_t kvs_cursor_ttl;

    bool     transactions_enable;
    bool     cn_maint_disable;
    bool     cn_close_wait;
    bool     cn_diag_mode;
    bool     read_only;
    uint8_t  perfc_level;
    uint8_t  cn_compaction_debug; /* 1=compact, 2=ingest */

    uint32_t cn_maint_delay;
    uint32_t cn_split_size;
    uint32_t kvs_sfxlen;

    uint64_t cn_compact_kblk_ra;
    uint64_t cn_compact_vblk_ra;
    uint64_t cn_compact_vra;

    uint64_t cn_capped_ttl;
    uint64_t cn_capped_vra;

    uint64_t cn_cursor_seq;
    uint64_t cn_cursor_vra;
    bool     cn_cursor_kra;

    uint8_t  cn_mmap_kra_params;
    uint8_t  cn_mmap_vra_params;
    uint8_t  cn_mmap_wbt;
    uint32_t cn_mmap_vmax;

    bool     cn_bloom_create;
    bool     cn_bloom_preload;
    uint64_t cn_bloom_prob;
    uint64_t cn_bloom_capped;

    uint64_t cn_kcachesz;

    uint64_t capped_evict_ttl;

    struct {
        enum vcomp_default deflt;
        enum vcomp_algorithm algorithm;
    } compression;

    char mclass_policy[HSE_MPOLICY_NAME_LEN_MAX];
};

const struct param_spec *
kvs_rparams_pspecs_get(size_t *pspecs_sz) HSE_RETURNS_NONNULL;

struct kvs_rparams
kvs_rparams_defaults() HSE_CONST;

merr_t
kvs_rparams_get(
    const struct kvs_rparams *params,
    const char *              param,
    char *                    buf,
    size_t                    buf_sz,
    size_t *                  needed_sz);

merr_t
kvs_rparams_set(
    const struct kvs_rparams *params,
    const char *              param,
    const char *              value);

cJSON *
kvs_rparams_to_json(const struct kvs_rparams *params);

#endif /* HSE_KVS_RPARAMS_H */
