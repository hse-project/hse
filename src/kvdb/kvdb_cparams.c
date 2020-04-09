/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/logging.h>
#include <hse_util/platform.h>
#include <hse_util/config.h>
#include <hse_util/param.h>
#include <hse_util/event_counter.h>

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvdb_cparams.h>

static struct kvdb_cparams kvdb_cp_ref;

#define CPARAMS_MAGIC 0x6264766b5043ul /* ascii CPkvdb */

static struct param_inst kvdb_cp_table[] = {
    PARAM_INST_U64_EXP(kvdb_cp_ref.dur_capacity, "dur_capacity", "durability capacity in MiB"),
    PARAM_INST_END
};

void
kvdb_cparams_table_reset(void)
{
    kvdb_cp_ref = kvdb_cparams_defaults();
}

struct param_inst *
kvdb_cparams_table(void)
{
    return kvdb_cp_table;
}

struct kvdb_cparams
kvdb_cparams_defaults(void)
{
    struct kvdb_cparams params = {
        .dur_capacity = 6144, /*  6 GiB */
        .cpmagic = CPARAMS_MAGIC,
    };

    return params;
}

static void
get_param_name(int index, char *buf, size_t buf_len)
{
    char *key;
    int   len;

    key = kvdb_cp_table[index].pi_type.param_token;
    len = strcspn(key, "=");

    if (len > buf_len) {
        buf[0] = '\0';
        return;
    }

    strncpy(buf, key, len);
    buf[len] = '\0';
}

char *
kvdb_cparams_help(char *buf, size_t buf_sz, struct kvdb_cparams *cp)
{
    struct kvdb_cparams def;
    int                 n = NELEM(kvdb_cp_table) - 1; /* skip PARAM_INST_END */

    if (!cp) {
        /* Caller did not provide the default values to be printed.
         * Use system defaults. */
        def = kvdb_cparams_defaults();
        cp = &def;
    }

    return params_help(buf, buf_sz, cp, kvdb_cp_table, n, &kvdb_cp_ref);
}

int
kvdb_cparams_validate(struct kvdb_cparams *cparams)
{
    if (ev(!cparams))
        return EINVAL;

    if (cparams->cpmagic != CPARAMS_MAGIC) {
        hse_log(HSE_ERR "KVDB create-time parameters not properly "
                        "initialized (use kvdb_cparams_defaults())");
        return EINVAL;
    }

    return 0;
}

void
kvdb_cparams_print(struct kvdb_cparams *cparams)
{
    int n = NELEM(kvdb_cp_table) - 1; /* skip PARAM_INST_END */

    if (ev(!cparams))
        return;

    params_print(kvdb_cp_table, n, "kvdb_cparams", cparams, &kvdb_cp_ref);
}

int
kvdb_cparams_parse(
    int                  argc,
    char **              argv,
    struct kvdb_cparams *params,
    int *                next_arg,
    unsigned int         flag)
{
    merr_t err;

    kvdb_cp_ref = *params;

    err = process_params(argc, argv, kvdb_cp_table, next_arg, flag);
    if (ev(err))
        return merr_errno(err);

    *params = kvdb_cp_ref;

    return 0;
}

void
kvdb_cparams_diff(
    struct kvdb_cparams *cp,
    void *               arg,
    void (*callback)(const char *, const char *, void *))
{
    int                 i;
    int                 num_elems = NELEM(kvdb_cp_table) - 1;
    struct kvdb_cparams def = kvdb_cparams_defaults();

    for (i = 0; i < num_elems; i++) {
        char   valstr[DT_PATH_ELEMENT_LEN];
        char   param_name[DT_PATH_ELEMENT_LEN];
        size_t n = kvdb_cp_table[i].pi_type.param_size;
        size_t offset = (kvdb_cp_table[i].pi_value - (void *)&kvdb_cp_ref);

        if (bcmp((void *)&def + offset, (void *)cp + offset, n)) {
            get_param_name(i, param_name, sizeof(param_name));
            kvdb_cp_table[i].pi_type.param_val_to_str(
                valstr, sizeof(valstr), (void *)cp + offset, NELEM(valstr));
            callback(param_name, valstr, arg);
        }
    }
}
