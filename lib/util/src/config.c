/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define NO_ERROR_COUNTER

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/string.h>
#include <hse_util/logging.h>
#include <hse_util/parse_num.h>
#include <hse_util/data_tree.h>
#include <hse_util/config.h>

static size_t
set_handler(struct dt_element *dte, struct dt_set_parameters *dsp)
{
    struct hse_config *mc = (struct hse_config *)dte->dte_data;
    char               buf[128];
    merr_t             err;

    if (!mc->writable)
        return 0;

    /* If there is a validator, try it first */
    if (mc->validator) {
        err = mc->validator(mc->instance, mc->path, dsp, mc->dfault, mc->rock, buf, 128);
        if (err)
            return 0;
    }
    /**
     * Which setter should we use?
     * - if customer provided an setter, we use it, else
     * - match sizes and assume that it is an unsigned whatever.
     */
    if (mc->set) {
        mc->set(dte, dsp);
    } else {
        if (dsp->field == DT_FIELD_DATA) {
            switch (mc->data_sz) {

                case 1: {
                    u8 val;

                    err = parse_u8(dsp->value, &val);
                    if (err == 0)
                        memcpy(mc->data, &val, sizeof(val));
                } break;
                case 2: {
                    u16 val;

                    err = parse_u16(dsp->value, &val);
                    if (err == 0)
                        memcpy(mc->data, &val, sizeof(val));
                } break;
                case 4: {
                    u32 val;

                    err = parse_u32(dsp->value, &val);
                    if (err == 0)
                        memcpy(mc->data, &val, sizeof(val));
                } break;
                case 8: {
                    u64 val;

                    err = parse_u64(dsp->value, &val);
                    if (err == 0)
                        memcpy(mc->data, &val, sizeof(val));
                } break;
            }
        } else { /* set without 'field', so reset to default */
            memcpy(mc->data, mc->dfault, mc->data_sz);
        }
    }
    ev_get_timestamp(&mc->change_timestamp);
    return 1;
}

size_t
config_set_handler(struct dt_element *dte, struct dt_set_parameters *dsp)
{
    return set_handler(dte, dsp);
}

static const char *
skip(const char *prefix, const char *string)
{
    size_t prefixlen = strlen(prefix);

    if (prefixlen > strlen(string) || strncmp(string, prefix, prefixlen))
        prefixlen = 0;

    return string + prefixlen;
}

/**
 * emit_handler output fits into a YAML document. spacing is driven by
 * YAML context.
 *
 * A config variable (with its preceding data and header elements
 * looks like this:
 * data:
 *   - config:
 *     - path: /data/config/kvdb/cn/spill/kvdb1
 *       current: 2
 *       default: 1
 *       changed: 09/14/2016 19:41:20:150354Z
 *
 * Fields are indented 6 spaces.
 */
static size_t
emit_handler(struct dt_element *dte, struct yaml_context *yc)
{
    struct hse_config *mc = dte->dte_data;
    char               buf[128];
    size_t             bufsz = sizeof(buf);
    const char *       path;
    u64                t;

    assert(dte);
    assert(dte->dte_type != DT_TYPE_INVALID);

    path = skip("/data/config/", dte->dte_path);
    yaml_start_element(yc, "path", path);

    /**
     * Which emitter should we use?
     * - if customer provided an emitter, we use it, else
     * - match sizes and assume that it is an unsigned whatever.
     */
    if (mc->emit) {
        mc->emit(dte, yc);
    } else {
        unsigned long long val, dflt;

        switch (mc->data_sz) {
            case 1:
                val = *(u8 *)mc->data;
                dflt = *(u8 *)mc->dfault;
                break;

            case 2:
                val = *(u16 *)mc->data;
                dflt = *(u16 *)mc->dfault;
                break;

            case 4:
                val = *(u32 *)mc->data;
                dflt = *(u32 *)mc->dfault;
                break;

            case 8:
                val = *(u64 *)mc->data;
                dflt = *(u64 *)mc->dfault;
                break;

            default:
                val = dflt = -1;
                break;
        }

        snprintf(buf, bufsz, "0x%llx", val);
        yaml_element_field(yc, "current", buf);

        snprintf(buf, bufsz, "0x%llx", dflt);
        yaml_element_field(yc, "default", buf);
    }

    t = atomic64_read(&mc->change_timestamp);
    if (t != 0) {
        snprintf_timestamp(buf, bufsz, &mc->change_timestamp);
        yaml_element_field(yc, "changed", buf);
    }

    yaml_element_bool(yc, "writable", mc->writable);
    yaml_end_element(yc);

    return 1;
}

static size_t
count_handler(struct dt_element *element)
{
    return 1;
}

static size_t
log_handler(struct dt_element *dte, int log_level)
{

    struct hse_config *cfg = (struct hse_config *)dte->dte_data;
    void *             av[] = { cfg, 0 };

    /* [HSE_REVISIT] Do we use this logging feature anywhere???
     */
    hse_xlog(HSE_INFO "@@c", av);

    return 1;
}

static size_t
remove_handler(struct dt_element *dte)
{
    free(dte->dte_data);
    free(dte);
    return 0;
}

struct dt_element_ops config_ops = {
    .emit = emit_handler,
    .log = log_handler,
    .set = set_handler,
    .count = count_handler,
    .remove = remove_handler,
};

static size_t
root_emit_handler(struct dt_element *me, struct yaml_context *yc)
{
    yaml_start_element_type(yc, "config");

    return 1;
}

static size_t
root_remove_handler(struct dt_element *element)
{
    /* Whole of data_tree must have been removed...*/
    return 0;
}

static struct dt_element_ops config_root_ops = {
    .emit = root_emit_handler,
    .remove = root_remove_handler,
};

size_t
bool_set(struct dt_element *dte, struct dt_set_parameters *dsp)
{
    struct hse_config *mc = (struct hse_config *)dte->dte_data;

    if (!strcasecmp(dsp->value, "true"))
        *(bool *)mc->data = true;
    else
        *(bool *)mc->data = false;

    return 1;
}

size_t
bool_emit(struct dt_element *dte, struct yaml_context *yc)
{
    struct hse_config *mc = dte->dte_data;

    yaml_element_bool(yc, "current", *(bool *)mc->data);
    yaml_element_bool(yc, "default", *(bool *)mc->dfault);

    return 1;
}

size_t
string_set(struct dt_element *dte, struct dt_set_parameters *dsp)
{
    struct hse_config *mc = (struct hse_config *)dte->dte_data;

    if (dsp->field == 0) {
        /* Reset to default */
        if (mc->dfault) {
            strlcpy((char *)mc->data, (char *)mc->dfault, mc->data_sz);
            return 1;
        }
    }

    if (dsp->value) {
        strlcpy(mc->data, dsp->value, mc->data_sz);
        return 1;
    }

    return 0;
}

size_t
string_emit(struct dt_element *dte, struct yaml_context *yc)
{
    struct hse_config *mc = (struct hse_config *)dte->dte_data;

    yaml_element_field(yc, "current", (char *)mc->data);

    if (mc->dfault)
        yaml_element_field(yc, "default", (char *)mc->dfault);

    return 1;
}

/**
 * Install the root node for config variables. This is important because we
 * need to identify it as a ROOT node to get the write emit() behavior.
 */

void
config_init(void)
{
    static struct hse_config mc;
    static struct dt_element dte;

    memset(&mc, 0, sizeof(mc));
    memset(&dte, 0, sizeof(dte));

    dte.dte_data = &mc;
    dte.dte_ops = &config_root_ops;
    dte.dte_type = DT_TYPE_ROOT;
    strncpy(dte.dte_path, "/data/config", sizeof(dte.dte_path));

    dt_add(dt_data_tree, &dte);
}

struct hse_config *
hse_config(
    const char *      component,
    const char *      instance,
    const char *      path,
    void *            data,
    size_t            data_sz,
    void *            dfault,
    validator_t *     validator,
    void *            rock,
    dt_emit_handler_t emit,
    dt_set_handler_t  set,
    param_show_t      show,
    bool              writable)
{
    struct dt_element *dte;
    struct hse_config *cfg;

    dte = calloc(1, sizeof(*dte));
    if (ev(!dte))
        return NULL;

    cfg = calloc(1, sizeof(*cfg));
    if (ev(!cfg)) {
        free(dte);
        return NULL;
    }

    dte->dte_ops = &config_ops;
    dte->dte_data = cfg;
    dte->dte_type = DT_TYPE_DONT_CARE;

    strlcpy(cfg->instance, instance, DT_PATH_ELEMENT_LEN);
    strlcpy(cfg->path, path, DT_PATH_ELEMENT_LEN);
    cfg->data = data;
    cfg->data_sz = data_sz;
    cfg->dfault = dfault;
    cfg->validator = validator;
    cfg->emit = emit;
    cfg->set = set;
    cfg->show = show;
    cfg->rock = rock;
    cfg->writable = writable;

    snprintf(dte->dte_path, DT_PATH_LEN, "/data/config/%s/%s/%s", component, path, instance);
    dt_add(dt_data_tree, dte);

    return cfg;
}
