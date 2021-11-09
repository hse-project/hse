/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_KVDB_META_H
#define HSE_KVDB_KVDB_META_H

/* MTF_MOCK_DECL(kvdb_meta) */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <mpool/mpool.h>
#include <hse_util/hse_err.h>

struct kvdb_meta {
    unsigned int km_version;
    unsigned int km_omf_version; /* global OMF version */
    struct {
        uint64_t oid1;
        uint64_t oid2;
    } km_cndb;
    struct {
        uint64_t oid1;
        uint64_t oid2;
    } km_wal;
    struct {
        char path[PATH_MAX];
    } km_storage[MP_MED_COUNT];
};

/**
 * Creates a kvdb.meta file in the KVDB home
 *
 * @param kvdb_home: KVDB home
 */
/* MTF_MOCK */
merr_t
kvdb_meta_create(const char *kvdb_home);

/**
 * Removes a kvdb.meta file from the KVDB home
 *
 * @param kvdb_home: KVDB home
 */
/* MTF_MOCK */
merr_t
kvdb_meta_destroy(const char *kvdb_home);

/**
 * Serializes KVDB metadata into the kvdb.meta file
 *
 * @param meta: KVDB metadata
 * @param kvdb_home: KVDB home
 * @returns Error status
 * @retval 0 on succes
 * @retval !0 on error
 */
/* MTF_MOCK */
merr_t
kvdb_meta_serialize(const struct kvdb_meta *meta, const char *kvdb_home);

/**
 * Deserializes the kvdb.meta file into a KVDB metadata object
 *
 * @param meta: KVDB metadata
 * @param kvdb_home: KVDB home
 * @returns Error status
 * @retval 0 on succes
 * @retval !0 on error
 */
/* MTF_MOCK */
merr_t
kvdb_meta_deserialize(struct kvdb_meta *meta, const char *kvdb_home);

/**
 * Upgrade KVDB meta
 *
 * @param meta: KVDB metadata
 * @param kvdb_home: KVDB home
 * @returns Error status
 * @retval 0 on succes
 * @retval !0 on error
 */
/* MTF_MOCK */
merr_t
kvdb_meta_upgrade(struct kvdb_meta *const meta, const char *const kvdb_home);

/**
 * Add new mclass storage paths to the kvdb.meta file
 *
 * @param meta: KVDB metadata
 * @param kvdb_home: KVDB home
 * @param cparams: mpool create params
 * @returns Error status
 * @retval 0 on succes
 * @retval !0 on error
 */
/* MTF_MOCK */
merr_t
kvdb_meta_storage_add(
    struct kvdb_meta           *meta,
    const char                 *kvdb_home,
    const struct mpool_cparams *cparams);

/**
 * Appends to a KVDB meta object with media class paths
 *
 * @param meta: KVDB metadata
 * @param kvdb_home: KVDB home
 * @param params: mpool cparams
 * @returns Error status
 * @retval 0 on succes
 * @retval !0 on error
 */
/* MTF_MOCK */
void
kvdb_meta_from_mpool_cparams(
    struct kvdb_meta *          meta,
    const char *                kvdb_home,
    const struct mpool_cparams *params);

/**
 * Deserializes KVDB metadata into mpool rparams
 *
 * @param meta: KVDB metadata
 * @param kvdb_home: KVDB home
 * @param params: mpool rparams
 * @returns Error status
 * @retval 0 on succes
 * @retval !0 on error
 */
/* MTF_MOCK */
merr_t
kvdb_meta_to_mpool_rparams(
    const struct kvdb_meta *meta,
    const char *            kvdb_home,
    struct mpool_rparams *  params);

/**
 * Deserializes KVDB metadata into mpool dparams
 *
 * @param meta: KVDB metadata
 * @param kvdb_home: KVDB home
 * @param params: mpool dparams
 * @returns Error status
 * @retval 0 on succes
 * @retval !0 on error
 */
/* MTF_MOCK */
merr_t
kvdb_meta_to_mpool_dparams(
    const struct kvdb_meta *const meta,
    const char *const             kvdb_home,
    struct mpool_dparams *const   params);

#if HSE_MOCKING
#include "kvdb_meta_ut.h"
#endif

#endif
