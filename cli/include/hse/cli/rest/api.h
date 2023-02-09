/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#ifndef HSE_CLI_REST_API_H
#define HSE_CLI_REST_API_H

#include <stdbool.h>
#include <stddef.h>

#include <hse/types.h>

#include <hse/error/merr.h>

struct hse_kvdb_compact_status;

merr_t
rest_get_param(char **value, const char *param, bool pretty);

merr_t
rest_get_params(char **config, bool pretty);

merr_t
rest_set_param(const char *param, const char *value);

merr_t
rest_kvdb_cancel_compaction(const char *alias);

merr_t
rest_kvdb_compact(const char *alias, bool full);

void
rest_kvdb_free_kvs_names(char **namev);

merr_t
rest_kvdb_get_compaction_status(struct hse_kvdb_compact_status *status, const char *alias);

merr_t
rest_kvdb_get_configured_mclasses(bool configured[static HSE_MCLASS_COUNT], const char *alias);

merr_t
rest_kvdb_get_home(char **home, const char *alias);

merr_t
rest_kvdb_get_kvs_names(size_t *namec, char ***namev, const char *alias);

merr_t
rest_kvdb_get_mclass_info(struct hse_mclass_info *info, const char *alias, enum hse_mclass mclass);

merr_t
rest_kvdb_get_param(char **value, const char *alias, const char *param, bool pretty);

merr_t
rest_kvdb_get_params(char **config, const char *alias, bool pretty);

merr_t
rest_kvdb_set_param(const char *alias, const char *param, const char *value);

merr_t
rest_kvs_get_param(
    char **value,
    const char *alias,
    const char *name,
    const char *param,
    bool pretty);

merr_t
rest_kvs_get_params(const char *alias, const char *name, bool pretty, char **config);

merr_t
rest_kvs_set_param(const char *alias, const char *name, const char *param, const char *value);

#endif
