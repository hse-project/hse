/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/logging.h>
#include <hse_util/platform.h>
#include <hse_util/config.h>
#include <hse_util/param.h>
#include <hse_util/event_counter.h>

#include <hse/hse_limits.h>

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvs_cparams.h>

/* Unlike rparams, cparams API is not thread safe. There should always be at
 * most one thread using it.
 */

#define CPARAMS_MAGIC 0x73766b5043ul /* ascii CPkvs */

static struct kvs_cparams kvs_cp_ref;
static struct param_inst  kvs_cp_table[] = {
    PARAM_INST_U32_EXP(kvs_cp_ref.cp_fanout, "fanout", "cN tree fanout"),
    PARAM_INST_U32(kvs_cp_ref.cp_pfx_len, "pfx_len", "Key prefix length"),
    PARAM_INST_U32_EXP(
        kvs_cp_ref.cp_pfx_pivot,
        "pfx_pivot",
        "first level to spill with full hash (0=root)"),
    PARAM_INST_U32_EXP(kvs_cp_ref.cp_kvs_ext01, "kvs_ext01", "kvs_ext01"),
    PARAM_INST_U32(kvs_cp_ref.cp_sfx_len, "sfx_len", "Key suffix length"),
    PARAM_INST_END
};

void
kvs_cparams_table_reset(void)
{
    kvs_cp_ref = kvs_cparams_defaults();
}

struct param_inst *
kvs_cparams_table(void)
{
    return kvs_cp_table;
}

struct kvs_cparams
kvs_cparams_defaults(void)
{
    struct kvs_cparams params = { .cp_fanout = 16,
                                  .cp_pfx_len = 0,
                                  .cp_pfx_pivot = 2, /* only used when pfx_len > 0 */
                                  .cp_kvs_ext01 = 0,
                                  .cp_cpmagic = CPARAMS_MAGIC };

    return params;
}

static void
get_param_name(int index, char *buf, size_t buf_len)
{
    char *key;
    int   len;

    key = kvs_cp_table[index].pi_type.param_token;
    len = strcspn(key, "=");

    if (len > buf_len) {
        buf[0] = '\0';
        return;
    }

    strncpy(buf, key, len);
    buf[len] = '\0';
}

char *
kvs_cparams_help(char *buf, size_t buf_sz, struct kvs_cparams *cparams)
{
    struct kvs_cparams def;
    int                n = NELEM(kvs_cp_table) - 1; /* skip PARAM_INST_END */

    if (!cparams) {
        /* Caller did not provide the default values to be printed.
         * Use system defaults. */
        def = kvs_cparams_defaults();
        cparams = &def;
    }

    return params_help(buf, buf_sz, cparams, kvs_cp_table, n, &kvs_cp_ref);
}

void
kvs_cparams_print(struct kvs_cparams *cparams)
{
    int n = NELEM(kvs_cp_table) - 1; /* skip PARAM_INST_END */

    if (ev(!cparams))
        return;

    params_print(kvs_cp_table, n, "kvs_cparams", cparams, &kvs_cp_ref);
}

int
kvs_cparams_validate(struct kvs_cparams *cparams)
{
    bool valid_fanout;
    u32  f;

    if (ev(!cparams))
        return EINVAL;

    if (cparams->cp_cpmagic != CPARAMS_MAGIC) {
        hse_log(HSE_ERR "KVS create-time parameters not properly "
                        "initialized (use kvs_cparams_defaults())");
        return EINVAL;
    }

    /* Validate fanout */
    valid_fanout = false;
    for (f = CN_FANOUT_MIN; f <= CN_FANOUT_MAX; f = f * 2) {
        if (f == cparams->cp_fanout) {
            valid_fanout = true;
            break;
        }
    }

    if (!valid_fanout) {
        hse_log(
            HSE_ERR "Invalid KVS fanout (%u),"
                    " must be power of 2 between %u and %u inclusive.",
            cparams->cp_fanout,
            CN_FANOUT_MIN,
            CN_FANOUT_MAX);
        return EINVAL;
    }

    /* Validate key prefix length */
    if (cparams->cp_pfx_len > HSE_KVS_MAX_PFXLEN) {
        hse_log(
            HSE_ERR "Invalid KVS prefix length (%u),"
                    " cannot be greater than %u",
            cparams->cp_pfx_len,
            HSE_KVS_MAX_PFXLEN);
        return EINVAL;
    }

    return 0;
}

int
kvs_cparams_parse(int argc, char **argv, struct kvs_cparams *params, int *next_arg)
{
    merr_t err;

    kvs_cp_ref = *params;
    err = process_params(argc, argv, kvs_cp_table, next_arg, 0);
    if (!ev(err)) {
        *params = kvs_cp_ref;
        return 0;
    }

    return merr_errno(err);
}

void
kvs_cparams_diff(
    struct kvs_cparams *cp,
    void *              arg,
    void (*callback)(const char *, const char *, void *))
{
    int                i;
    int                num_elems = NELEM(kvs_cp_table) - 1;
    struct kvs_cparams def = kvs_cparams_defaults();

    for (i = 0; i < num_elems; i++) {
        char   valstr[DT_PATH_ELEMENT_LEN];
        char   param_name[DT_PATH_ELEMENT_LEN];
        size_t n = kvs_cp_table[i].pi_type.param_size;
        size_t offset = kvs_cp_table[i].pi_value - (void *)&kvs_cp_ref;

        if (bcmp((void *)&def + offset, (void *)cp + offset, n)) {
            get_param_name(i, param_name, sizeof(param_name));
            kvs_cp_table[i].pi_type.param_val_to_str(
                valstr, sizeof(valstr), (void *)cp + offset, 1);
            callback(param_name, valstr, arg);
        }
    }
}
