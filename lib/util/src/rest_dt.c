/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/logging.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>

#include <hse_util/data_tree.h>
#include <hse_util/rest_api.h>
#include <hse_util/spinlock.h>
#include <hse_util/string.h>

/* rest hooks for dt */
merr_t
rest_dt_put(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    struct dt_tree *            tree;
    struct dt_set_parameters    dsp;
    struct dt_element *         dte;
    union dt_iterate_parameters dip = { .dsp = &dsp };
    struct rest_kv *            kv;
    struct yaml_context         yc = { 0 };
    char                        buf[1024 * 1024];

    /* only support rest queries in URI */
    if (info->data)
        return merr(ev(EPROTONOSUPPORT));

    yc.yaml_indent = 0;
    yc.yaml_offset = 0;
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = sizeof(buf);
    yc.yaml_emit = NULL;

    tree = dt_get_tree("/data");
    if (!tree) {
        const char msg[] = "No data tree found\n";

        if (write(info->resp_fd, msg, sizeof(msg) - 1) != sizeof(msg) - 1)
            return merr(EIO);

        return merr(ev(ENOENT));
    }

    /* Separate out the path and arguments */
    dsp.path = calloc(1, strlen(path) + 2);
    if (!dsp.path)
        return merr(ev(ENOMEM));

    sprintf(dsp.path, "/%s", path);

    /* Check if path is valid */
    dte = dt_find(tree, dsp.path, 0);
    if (!dte) {
        size_t n = snprintf(buf, sizeof(buf), "Invalid path: %s\n", dsp.path);

        free(dsp.path);
        if (write(info->resp_fd, buf, n) != n)
            return merr(EIO);

        return merr(ev(ENXIO));
    }

    /* Parse the arguments and extract key=value pairs*/
    yaml_start_element_type(&yc, "Attempted PUTs");
    while ((kv = rest_kv_next(iter)) != 0) {
        dsp.field = dt_get_field(kv->key);
        if (dsp.field == DT_FIELD_INVALID)
            continue; /* move on */

        dsp.value = kv->value;
        dsp.value_len = strlen(dsp.value);

        dt_iterate_cmd(tree, DT_OP_SET, dsp.path, &dip, 0, 0, 0);

        yaml_start_element(&yc, "path", dsp.path);
        yaml_element_field(&yc, "field", kv->key);
        yaml_element_field(&yc, "value", kv->value);
        yaml_end_element(&yc);
    }
    yaml_end_element_type(&yc);

    free(dsp.path);

    if (write(info->resp_fd, buf, yc.yaml_offset) != yc.yaml_offset)
        return merr(EIO);

    return 0;
}

merr_t
rest_dt_get(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    struct dt_tree *            tree;
    struct rest_kv *            kv = 0;
    char *                      fld, *val;
    size_t                      pathsz;
    size_t                      bufsz;
    char *                      buf;
    struct yaml_context         yc = { 0 };
    union dt_iterate_parameters dip = { .yc = &yc };

    switch (rest_kv_count(iter)) {
        case 0:
            fld = val = 0;
            break;
        case 1:
            kv = rest_kv_next(iter);
            fld = kv->key;
            val = kv->value;
            break;
        default:
            return merr(ev(E2BIG));
    }

    tree = dt_get_tree("/data");
    if (!tree)
        return merr(ev(ENOENT));

    pathsz = strlen(path) + 2;
    bufsz = 1048576 + pathsz;
    bufsz = ALIGN(bufsz, 1048576 * 2);

    buf = malloc(bufsz);
    if (!buf)
        return merr(ENOMEM);

    sprintf(buf, "/%s", path);

    yc.yaml_indent = 0;
    yc.yaml_offset = 0;
    yc.yaml_emit = NULL;
    yc.yaml_buf_sz = bufsz - ALIGN(pathsz, 8);
    yc.yaml_buf = buf + ALIGN(pathsz, 8);

    if (dt_iterate_cmd(tree, DT_OP_EMIT, buf, &dip, 0, fld, val) > 0)
        rest_write_safe(info->resp_fd, yc.yaml_buf, yc.yaml_offset);

    free(buf);

    return 0;
}
