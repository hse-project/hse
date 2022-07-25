/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_KVDB_META_H
#define HSE_KVDB_KVDB_META_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <hse/error/merr.h>
#include <hse/mpool/mpool.h>

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
    } km_storage[HSE_MCLASS_COUNT];
};

/**
 * Creates a kvdb.meta file in the KVDB home
 *
 * @param kvdb_home: KVDB home
 */
merr_t
kvdb_meta_create(const char *kvdb_home) HSE_MOCK;

/**
 * Removes a kvdb.meta file from the KVDB home
 *
 * @param kvdb_home: KVDB home
 */
merr_t
kvdb_meta_destroy(const char *kvdb_home) HSE_MOCK;

/**
 * Serializes KVDB metadata into the kvdb.meta file
 *
 * @param meta: KVDB metadata
 * @param kvdb_home: KVDB home
 * @returns Error status
 * @retval 0 on succes
 * @retval !0 on error
 */
merr_t
kvdb_meta_serialize(const struct kvdb_meta *meta, const char *kvdb_home) HSE_MOCK;

/**
 * Deserializes the kvdb.meta file into a KVDB metadata object
 *
 * @param meta: KVDB metadata
 * @param kvdb_home: KVDB home
 * @returns Error status
 * @retval 0 on succes
 * @retval !0 on error
 */
merr_t
kvdb_meta_deserialize(struct kvdb_meta *meta, const char *kvdb_home) HSE_MOCK;

/**
 * Upgrade KVDB meta
 *
 * @param meta: KVDB metadata
 * @param kvdb_home: KVDB home
 * @returns Error status
 * @retval 0 on succes
 * @retval !0 on error
 */
merr_t
kvdb_meta_upgrade(struct kvdb_meta * const meta, const char * const kvdb_home) HSE_MOCK;

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
merr_t
kvdb_meta_storage_add(
    struct kvdb_meta *meta,
    const char *kvdb_home,
    const struct mpool_cparams *cparams) HSE_MOCK;

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
void
kvdb_meta_from_mpool_cparams(
    struct kvdb_meta *meta,
    const char *kvdb_home,
    const struct mpool_cparams *params) HSE_MOCK;

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
merr_t
kvdb_meta_to_mpool_rparams(
    const struct kvdb_meta *meta,
    const char *kvdb_home,
    struct mpool_rparams *params) HSE_MOCK;

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
merr_t
kvdb_meta_to_mpool_dparams(
    const struct kvdb_meta * const meta,
    const char * const kvdb_home,
    struct mpool_dparams * const params) HSE_MOCK;

#if HSE_MOCKING
#include "kvdb_meta_ut.h"
#endif

#endif
