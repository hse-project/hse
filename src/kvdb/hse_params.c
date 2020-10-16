/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/hse.h>
#include <hse/hse_experimental.h>

#include <hse_util/platform.h>
#include <hse_util/param.h>
#include <hse_util/string.h>
#include <hse_util/hse_params_helper.h>

#include <hse_ikvdb/wp.h>
#include <hse_ikvdb/hse_params_internal.h>
#include <hse_ikvdb/mclass_policy.h>

#define HP_DICT_ENTRIES_MAX 512
#define HP_DICT_LEN_MAX 256
#define HP_ERR_BUF_SZ 1024

/* [HSE_REVISIT]
 * Temporary implementation for mocking a dictionary. Since the params
 * are stored in an array, get and set operations will be O(n). Using
 * a third party library such as libdict will allow for more efficent
 * operations.
 */
struct hse_params {
    int  hp_next;
    char hp_keys[HP_DICT_ENTRIES_MAX][HP_DICT_LEN_MAX];
    char hp_vals[HP_DICT_ENTRIES_MAX][HP_DICT_LEN_MAX];
    char hp_err[HP_ERR_BUF_SZ];
};

static void
key_split(const char *key, char *component, char *param)
{
    bool  equals = false;
    char *split, *iter;

    split = iter = (char *)key;

    while (*iter != '\0') {
        if (*iter == '=')
            equals = true;
        if (*iter++ == '.' && !equals)
            split = iter;
    }

    strlcpy(component, key, split - key + 1);
    strlcpy(param, split, iter - split + 1);
}

static void
key_combine(char *dst, const char *filter, const char *token)
{
    size_t filter_len = strlen(filter);
    size_t token_len = strcspn(token, "=");

    strlcpy(dst, filter, filter_len + 1);
    strlcpy(dst + filter_len, token, token_len + 1);
}

static int
key_depth(const char *key)
{
    int   depth = 0;
    char *iter = (char *)key;

    while (*iter != '\0') {
        if (*iter++ == '.')
            depth++;
    }

    return depth;
}

static bool
key_is_mclass_policy(const char *key)
{
    const char expect[] = "mclass_policies";

    return !strncmp(key, expect, sizeof(expect) - 1);
}

static int
key_validate(const char *key)
{
    int depth = key_depth(key);

    if (strlen(key) > 4 && !strncmp(key, "kvdb", 4))
        return (depth > 0 && depth < 2);

    if (key_is_mclass_policy(key))
        return depth >= 1;

    return (depth > 0 && depth < 3);
}

static int
param_find(char *param, struct param_inst *table)
{
    int    i;
    char * token;
    size_t len;

    for (i = 0; true; i++) {
        token = table[i].pi_type.param_token;
        if (!token)
            break;

        len = strcspn(token, "=");

        if (strlen(param) == len && !strncmp(param, token, len))
            return i;
    }

    return -1;
}

static merr_t
param_validate(struct hse_params *params, const char *key, const char *val)
{
    merr_t err;
    int    i, index;
    char   component[HP_DICT_LEN_MAX], param[HP_DICT_LEN_MAX];

    struct param_inst *pi, *tables[4] = {
        kvdb_cparams_table(),
        kvdb_rparams_table(),
        kvs_cparams_table(),
        kvs_rparams_table(),
    };

    if (!key_validate(key))
        return merr(EINVAL);

    key_split(key, component, param);

    if (key_is_mclass_policy(component)) {
        int count = 0;

        if (!(strlen(param) > 0 && strlen(param) < HSE_MPOLICY_NAME_LEN_MAX))
            return merr(EINVAL);

        for (i = 0; i < params->hp_next; i++) {
            /* Check whether a media class policy with the same name exists */
            if (!strcmp(params->hp_keys[i], key))
                return merr(EINVAL);

            if (key_is_mclass_policy((const char *)params->hp_keys[i])) {
                count++;
                if (count >= HSE_MPOLICY_COUNT)
                    return merr(EINVAL);
            }
        }

        return 0;
    }

    for (i = 0; i < 4; i++) {
        pi = tables[i];
        index = param_find(param, pi);
        if (index >= 0)
            break;
    }

    if (index < 0)
        return merr(EINVAL);

    if ((index >= 0)) {
        err = pi[index].pi_type.param_str_to_val(
            val, pi[index].pi_value, pi[index].pi_type.param_size);
        if (ev(err))
            return merr(EINVAL);
    }

    /* Check that the media class policy requested for the KVS is defined. */
    if (strstr(param, "mclass_policy")) {
        char kname[HP_DICT_LEN_MAX];

        strcpy(kname, "mclass_policies.");
        strcat(kname, val);

        for (i = 0; i < params->hp_next; i++) {
            if (!strcmp(params->hp_keys[i], kname))
                return 0;
        }

        return merr(EINVAL);
    }

    return 0;
}

struct hse_params *
hse_params_clone(const struct hse_params *params)
{
    struct hse_params *clone;

    if (!params)
        return NULL;

    clone = malloc(sizeof(*clone));
    if (!clone)
        return NULL;

    *clone = *params;

    return clone;
}

void
hse_params_free(struct hse_params *params)
{
    free(params);
}

/* Public API */

hse_err_t
hse_params_create(struct hse_params **params)
{
    if (!params)
        return merr(EINVAL);

    *params = calloc(1, sizeof(struct hse_params));
    if (!*params)
        return merr(ENOMEM);

    /* Load the predefined media class policies */
    hse_params_from_string(*params, mclass_policy_get_default_policies());

    return 0;
}

uint64_t
hse_params_from_file(struct hse_params *params, const char *path)
{
    merr_t err;

    err = wp_parse(path, params, WP_FILE);
    if (err)
        strlcpy(
            params->hp_err, "hse_params: unable to parse specified path", sizeof(params->hp_err));

    return err;
}

uint64_t
hse_params_from_string(struct hse_params *params, const char *input)
{
    merr_t err;

    err = wp_parse(input, params, WP_STRING);
    if (err)
        strlcpy(
            params->hp_err, "hse_params: unable to parse specified string", sizeof(params->hp_err));

    return err;
}

uint64_t
hse_params_set(struct hse_params *params, const char *key, const char *val)
{
    int    i;
    merr_t err;

    if (!params) {
        strlcpy(params->hp_err, "hse_params: missing params arg", sizeof(params->hp_err));
        return merr(EINVAL);
    }

    if (!key) {
        strlcpy(params->hp_err, "hse_params: missing key arg", sizeof(params->hp_err));
        return merr(EINVAL);
    }

    if (!val) {
        strlcpy(params->hp_err, "hse_params: missing value arg", sizeof(params->hp_err));

        return merr(EINVAL);
    }

    if (params->hp_next >= HP_DICT_ENTRIES_MAX) {
        strlcpy(params->hp_err, "hse_params: dictionary out of space", sizeof(params->hp_err));
        return merr(ENOSPC);
    }

    if (strlen(key) > HP_DICT_LEN_MAX) {
        strlcpy(params->hp_err, "hse_params: specified key too long", sizeof(params->hp_err));
        return merr(EINVAL);
    }

    if (strlen(val) > HP_DICT_LEN_MAX) {
        strlcpy(params->hp_err, "hse_params: specified value too long", sizeof(params->hp_err));
        return merr(EINVAL);
    }

    err = param_validate(params, key, val);
    if (err) {
        strlcpy(params->hp_err, "hse_params: invalid key or value", sizeof(params->hp_err));
        return err;
    }

    for (i = 0; i < params->hp_next; i++) {
        if (!strcmp(params->hp_keys[i], key)) {
            strlcpy(params->hp_vals[i], val, sizeof(params->hp_vals[i]));
            return 0;
        }
    }

    strlcpy(params->hp_vals[params->hp_next], val, sizeof(params->hp_vals[params->hp_next]));

    strlcpy(params->hp_keys[params->hp_next], key, sizeof(params->hp_keys[params->hp_next]));

    params->hp_next++;

    return 0;
}

char *
hse_params_get(
    const struct hse_params *params,
    const char *             key,
    char *                   buf,
    size_t                   buf_sz,
    size_t *                 param_sz)
{
    int i, len;

    if (!params || !key || !buf)
        return NULL;

    for (i = 0; i < params->hp_next; i++) {
        if (!strcmp(params->hp_keys[i], key)) {
            len = strlcpy(buf, params->hp_vals[i], buf_sz);
            if (param_sz)
                *param_sz = len;

            return buf;
        }
    }

    return NULL;
}

char *
hse_params_err_exp(const struct hse_params *params, char *buf, size_t buf_sz)
{
    if (!params || !buf)
        return NULL;

    strlcpy(buf, params->hp_err, buf_sz);

    return buf;
}

void
hse_params_destroy(struct hse_params *params)
{
    hse_params_free(params);
}

/* Internals */

static merr_t
params_convert(
    const struct hse_params *params,
    struct param_inst *      table,
    void *                   base,
    const char *             filter)
{
    merr_t err = 0;
    int    i;

    if (!params || !table)
        return err;

    /* [HSE_REVISIT]
     * Offset Assumes that the first element in the table is the
     * first field in the struct. Need to remove the concept
     * of a ref struct so offsets can be calculated outside
     * of ikvdb.
     */

    for (i = 0; true; i++) {
        char   key[HP_DICT_LEN_MAX], result[HP_DICT_LEN_MAX];
        char * token;
        size_t offset;

        token = table[i].pi_type.param_token;
        if (!token)
            break;

        key_combine(key, filter, token);

        if (!hse_params_get(params, key, result, sizeof(result), 0))
            continue;

        /* Perform validation as late as possible to coincide with the
         * realization of a cparams or rparams struct from hse_params.
         */
        if (table[i].pi_type.param_range_check) {
            err = table[i].pi_type.param_range_check(
                table[i].pi_type.param_min, table[i].pi_type.param_max, table[i].pi_value);
            if (ev(err))
                return merr(EINVAL);
        }

        offset = table[i].pi_value - table[0].pi_value;

        table[i].pi_type.param_str_to_val(result, base + offset, table[i].pi_type.param_size);
    }

    return err;
}

merr_t
hse_params_to_kvdb_cparams(
    const struct hse_params *params,
    struct kvdb_cparams *    ref,
    struct kvdb_cparams *    out)
{
    merr_t err = 0;

    if (!out)
        return merr(EINVAL);

    struct kvdb_cparams cp = ref ? *ref : kvdb_cparams_defaults();
    struct param_inst * table = kvdb_cparams_table();

    err = params_convert(params, table, &cp, "kvdb.");
    if (err != 0)
        return err;

    memcpy(out, &cp, sizeof(struct kvdb_cparams));

    return err;
}

merr_t
hse_params_to_kvdb_rparams(
    const struct hse_params *params,
    struct kvdb_rparams *    ref,
    struct kvdb_rparams *    out)
{
    merr_t err = 0;

    if (!out)
        return merr(EINVAL);

    struct kvdb_rparams rp = ref ? *ref : kvdb_rparams_defaults();
    struct param_inst * table = kvdb_rparams_table();

    err = params_convert(params, table, &rp, "kvdb.");
    if (ev(err))
        return err;

    memcpy(out, &rp, sizeof(struct kvdb_rparams));

    return err;
}

void
hse_params_to_mclass_policies(
    const struct hse_params *params,
    struct mclass_policy *   policies,
    int                      entries)
{
    int                i, count = 0;
    merr_t             err = 0;
    struct hse_params *lparams = 0;

    if (!policies)
        return;

    if (!params) {
        err = hse_params_create(&lparams);
        if (ev(err))
            return;
        params = lparams;
    }

    for (i = 0; i < params->hp_next; i++) {
        if (key_is_mclass_policy((const char *)params->hp_keys[i])) {
            mclass_policy_init_from_string(
                &policies[count],
                (const char *)params->hp_keys[i],
                (const char *)params->hp_vals[i]);

            if (++count >= entries)
                break;
        }
    }

    if (lparams)
        hse_params_destroy(lparams);
}

merr_t
hse_params_to_kvs_cparams(
    const struct hse_params *params,
    const char *             kvs_name,
    struct kvs_cparams *     ref,
    struct kvs_cparams *     out)
{
    merr_t err = 0;

    if (!out)
        return merr(EINVAL);

    struct kvs_cparams cp = ref ? *ref : kvs_cparams_defaults();
    struct param_inst *table = kvs_cparams_table();

    err = params_convert(params, table, &cp, "kvs.");
    if (ev(err))
        return err;

    if (kvs_name) {
        char filter[HP_DICT_LEN_MAX];

        snprintf(filter, sizeof(filter), "kvs.%s.", kvs_name);
        err = params_convert(params, table, &cp, filter);
        if (ev(err))
            return err;
    }

    memcpy(out, &cp, sizeof(struct kvs_cparams));

    return err;
}

merr_t
hse_params_to_kvs_rparams(
    const struct hse_params *params,
    const char *             kvs_name,
    struct kvs_rparams *     ref,
    struct kvs_rparams *     out)
{
    merr_t err = 0;

    if (!out)
        return merr(EINVAL);

    struct kvs_rparams rp = ref ? *ref : kvs_rparams_defaults();
    struct param_inst *table = kvs_rparams_table();

    err = params_convert(params, table, &rp, "kvs.");
    if (ev(err))
        return err;

    if (kvs_name) {
        char filter[HP_DICT_LEN_MAX];

        snprintf(filter, sizeof(filter), "kvs.%s.", kvs_name);
        err = params_convert(params, table, &rp, filter);
        if (ev(err))
            return err;
    }

    memcpy(out, &rp, sizeof(struct kvs_rparams));

    return err;
}

/* Utilities */

/* [HSE_REVISIT]
 * Remove process_params from params.c and delete cparams/rparams parsers
 */
static merr_t
params_parse(
    int                argc,
    char **            argv,
    struct param_inst *pi,
    int *              next_arg,
    u32                flag,
    struct hse_params *params,
    const char *       filter)
{
    merr_t              err;
    struct match_token *table;
    substring_t         val;
    int                 arg;
    int                 index;
    int                 entry_cnt;

    err = param_gen_match_table(pi, &table, &entry_cnt);
    if (err)
        return err;

    for (arg = 0; arg < argc; arg++) {
        char component[HP_DICT_LEN_MAX], param[HP_DICT_LEN_MAX];

        key_split(argv[arg], component, param);

        if (strcmp(filter, component))
            continue;

        index = match_token(param, table, &val);
        if (index < 0)
            continue;

        if (flag && !(flag & pi[index].pi_flags))
            continue;

        if ((index >= 0) && (index < entry_cnt)) {
            char   key[128];
            size_t len = strcspn(param, "=");

            strcpy(key, component);
            strncpy(key + strlen(component), param, len);
            key[strlen(component) + len] = '\0';

            err = hse_params_set(params, key, val.from);
            if (err)
                return err;

            shuffle(argc, argv, 0, arg);
            if (next_arg)
                (*next_arg)++;
        }
    }

    param_free_match_table(table);
    return err;
}

uint64_t
hse_parse_cli(int argc, char **argv, int *next_arg, int flag, struct hse_params *params)
{
    merr_t             err;
    int                arg_cnt, offset = *next_arg;
    char **            arg_lst;
    struct param_inst *table;

    arg_cnt = argc;
    arg_lst = argv;
    table = kvdb_cparams_table();

    err = params_parse(arg_cnt, arg_lst, table, next_arg, flag, params, "kvdb.");
    if (err || argc == (*next_arg - offset))
        goto exit;

    arg_cnt = argc - (*next_arg - offset);
    arg_lst = argv + (*next_arg - offset);
    table = kvdb_rparams_table();

    err = params_parse(arg_cnt, arg_lst, table, next_arg, flag, params, "kvdb.");
    if (err || argc == (*next_arg - offset))
        goto exit;

    arg_cnt = argc - (*next_arg - offset);
    arg_lst = argv + (*next_arg - offset);
    table = kvs_cparams_table();

    err = params_parse(arg_cnt, arg_lst, table, next_arg, flag, params, "kvs.");
    if (err || argc == (*next_arg - offset))
        goto exit;

    arg_cnt = argc - (*next_arg - offset);
    arg_lst = argv + (*next_arg - offset);
    table = kvs_rparams_table();

    err = params_parse(arg_cnt, arg_lst, table, next_arg, flag, params, "kvs.");
    if (err || argc == (*next_arg - offset))
        goto exit;

exit:
    return err;
}

void
hse_get_param_table(void **table, char *target)
{
    if (!strcmp(target, "kvdb_cparams")) {
        kvdb_cparams_table_reset();
        *table = kvdb_cparams_table();
        return;
    }

    if (!strcmp(target, "kvdb_rparams")) {
        kvdb_rparams_table_reset();
        *table = kvdb_rparams_table();
        return;
    }

    if (!strcmp(target, "kvs_cparams")) {
        kvs_cparams_table_reset();
        *table = kvs_cparams_table();
        return;
    }

    if (!strcmp(target, "kvs_rparams")) {
        kvs_rparams_table_reset();
        *table = kvs_rparams_table();
        return;
    }

    *table = NULL;
}

char *
hse_generate_help(char *buf, size_t buf_sz, char *target)
{
    if (!strcmp(target, "kvdb_cparams")) {
        struct kvdb_cparams kvdb_cp;

        kvdb_cp = kvdb_cparams_defaults();
        return kvdb_cparams_help(buf, buf_sz, &kvdb_cp);
    }

    if (!strcmp(target, "kvdb_rparams")) {
        struct kvdb_rparams kvdb_rp;

        kvdb_rp = kvdb_rparams_defaults();
        return kvdb_rparams_help(buf, buf_sz, &kvdb_rp);
    }

    if (!strcmp(target, "kvs_cparams")) {
        struct kvs_cparams kvs_cp;

        kvs_cp = kvs_cparams_defaults();
        return kvs_cparams_help(buf, buf_sz, &kvs_cp);
    }

    if (!strcmp(target, "kvs_rparams")) {
        struct kvs_rparams kvs_rp;

        kvs_rp = kvs_rparams_defaults();
        return kvs_rparams_help(buf, buf_sz, &kvs_rp);
    }

    return NULL;
}
