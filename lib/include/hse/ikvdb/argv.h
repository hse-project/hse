/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CONFIG_ARGV_H
#define HSE_CONFIG_ARGV_H

#include <stddef.h>

#include <hse/ikvdb/kvdb_cparams.h>
#include <hse/ikvdb/kvdb_rparams.h>
#include <hse/ikvdb/kvs_cparams.h>
#include <hse/ikvdb/kvs_rparams.h>
#include <hse/ikvdb/hse_gparams.h>
#include <hse/error/merr.h>

/**
 * Deserialize list of key=value parameters to KVDB rparams
 *
 * @param paramc: number of parameters
 * @param paramv: list of key=value strings
 * @param params: params struct
 * @returns error status
 * @retval 0 success
 * @retval !0 failure
 */
merr_t
argv_deserialize_to_kvdb_rparams(
    size_t               paramc,
    const char *const *  paramv,
    struct kvdb_rparams *params);

/**
 * Deserialize list of key=value parameters to KVDB cparams
 *
 * @param paramc: number of parameters
 * @param paramv: list of key=value strings
 * @param params: params struct
 * @returns error status
 * @retval 0 success
 * @retval !0 failure
 */
merr_t
argv_deserialize_to_kvdb_cparams(
    size_t               paramc,
    const char *const *  paramv,
    struct kvdb_cparams *params);

/**
 * Deserialize list of key=value parameters to KVS rparams
 *
 * @param paramc: number of parameters
 * @param paramv: list of key=value strings
 * @param params: params struct
 * @returns error status
 * @retval 0 success
 * @retval !0 failure
 */
merr_t
argv_deserialize_to_kvs_rparams(
    size_t              paramc,
    const char *const * paramv,
    struct kvs_rparams *params);

/**
 * Deserialize list of key=value parameters to KVS cparams
 *
 * @param paramc: number of parameters
 * @param paramv: list of key=value strings
 * @param params: params struct
 * @returns error status
 * @retval 0 success
 * @retval !0 failure
 */
merr_t
argv_deserialize_to_kvs_cparams(
    size_t              paramc,
    const char *const * paramv,
    struct kvs_cparams *params);

/**
 * Deserialize list of key=value parameters to global params
 *
 * @param paramc: number of parameters
 * @param paramv: list of key=value strings
 * @param params: params struct
 * @returns error status
 * @retval 0 success
 * @retval !0 failure
 */
merr_t
argv_deserialize_to_hse_gparams(
    size_t              paramc,
    const char *const * paramv,
    struct hse_gparams *params);

#endif
