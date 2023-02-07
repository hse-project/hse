/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#ifndef HSE_CONFIG_HSE_GPARAMS_H
#define HSE_CONFIG_HSE_GPARAMS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/un.h>

#include <cjson/cJSON.h>

#include <hse/error/merr.h>
#include <hse/logging/logging.h>
#include <hse/util/compiler.h>

struct hse_gparams {
    uint64_t gp_c0kvs_ccache_sz_max;
    uint64_t gp_c0kvs_ccache_sz;
    uint64_t gp_c0kvs_cheap_sz;
    uint64_t gp_vlb_cache_sz;
    uint32_t gp_workqueue_tcdelay;
    uint32_t gp_workqueue_idle_ttl;
    uint8_t  gp_perfc_level;

    struct {
        bool enabled;
        char socket_path[sizeof(((struct sockaddr_un *)NULL)->sun_path)];
    } gp_rest;

    struct logging_params gp_logging;
};

extern struct hse_gparams hse_gparams;

const struct param_spec *
hse_gparams_pspecs_get(size_t *pspecs_sz) HSE_RETURNS_NONNULL;

struct hse_gparams
hse_gparams_defaults(void) HSE_CONST;

merr_t
hse_gparams_get(
    const struct hse_gparams *params,
    const char *              param,
    char *                    buf,
    size_t                    buf_sz,
    size_t *                  needed_sz);

merr_t
hse_gparams_set(
    struct hse_gparams *params,
    const char *        param,
    const char *        value);

/**
 * Deserialize a config to HSE gparams
 *
 * @param config Configuration
 * @param params HSE global params
 */
merr_t
hse_gparams_from_config(struct hse_gparams *params, cJSON *conf);

/**
 * Deserialize list of key=value parameters to HSE gparams
 *
 * @param paramc Number of parameters
 * @param paramv List of key=value strings
 * @param params Params struct
 *
 * @returns Error status
 * @retval 0 success
 * @retval !0 failure
 */
merr_t
hse_gparams_from_paramv(
    struct hse_gparams *params,
    size_t              paramc,
    const char *const * paramv);

cJSON *
hse_gparams_to_json(const struct hse_gparams *params) HSE_WARN_UNUSED_RESULT;

#endif
