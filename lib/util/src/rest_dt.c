/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_util/atomic.h>
#include <hse_util/logging.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>

#include <hse_util/data_tree.h>
#include <hse_util/rest_api.h>
#include <hse_util/spinlock.h>

#include <bsd/string.h>

/* rest hooks for dt */
merr_t
rest_dt_put(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    struct dt_set_parameters    dsp;
    struct dt_element *         dte;
    union dt_iterate_parameters dip = {.dsp = &dsp };
    struct rest_kv *            kv;
    struct yaml_context         yc = { 0 };
    char                       *buf;
    size_t                      bufsz = 1024 * 1024;
    merr_t                      err = 0;

    /* only support rest queries in URI */
    if (info->data)
        return merr(ev(EPROTONOSUPPORT));

    /* Separate out the path and arguments */
    dsp.path = calloc(1, strlen(path) + 2);
    if (!dsp.path)
        return merr(ev(ENOMEM));

    sprintf(dsp.path, "/%s", path);

    buf = malloc(bufsz);
    if (ev(!buf))
        return merr(ENOMEM);

    yc.yaml_indent = 0;
    yc.yaml_offset = 0;
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = bufsz;
    yc.yaml_emit = NULL;

    /* Check if path is valid */
    dte = dt_find(dsp.path, 0);
    if (!dte) {
        size_t n = snprintf(buf, bufsz, "Invalid path: %s\n", dsp.path);

        free(dsp.path);
        if (write(info->resp_fd, buf, n) != n) {
            err = merr(EIO);
            goto exit;
        }

        err = merr(ev(ENXIO));
        goto exit;
    }

    /* Parse the arguments and extract key=value pairs*/
    yaml_start_element_type(&yc, "Attempted PUTs");
    while ((kv = rest_kv_next(iter)) != 0) {
        size_t n;

        dsp.field = dt_get_field(kv->key);
        if (dsp.field == DT_FIELD_INVALID)
            continue; /* move on */

        dsp.value = kv->value;
        dsp.value_len = dsp.value ? strlen(dsp.value) : 0;

        printf("%s(%d): %s\n", kv->key, dsp.field, kv->value);
        n = dt_iterate_cmd(DT_OP_SET, dsp.path, &dip, 0, 0, 0);

        yaml_start_element(&yc, "path", dsp.path);
        yaml_element_field(&yc, "field", kv->key);
        yaml_element_field(&yc, "value", kv->value);
        yaml_field_fmt(&yc, "updates", "%zu", n);
        yaml_end_element(&yc);
    }
    yaml_end_element_type(&yc);

    free(dsp.path);

    if (write(info->resp_fd, buf, yc.yaml_offset) != yc.yaml_offset) {
        err = merr(EIO);
        goto exit;
    }

exit:
    free(buf);
    return err;
}

merr_t
rest_dt_get(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    static atomic_ulong rest_dt_get_bufsz = 128 * 1024;
    struct rest_kv *            kv = 0;
    char *                      fld, *val;
    size_t                      pathsz;
    size_t                      bufsz;
    char *                      buf;
    struct yaml_context         yc = { 0 };
    union dt_iterate_parameters dip = {.yc = &yc };
    char                        dt_path[PATH_MAX];

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

    pathsz = strlen(path) + 2;
    bufsz = rest_dt_get_bufsz;
    bufsz = ALIGN(pathsz, bufsz);

    buf = malloc(bufsz);
    if (!buf)
        return merr(ENOMEM);

    if (snprintf(buf, bufsz, "/%s", path) > bufsz) {
        free(buf);
        return merr(ENAMETOOLONG);
    }

    if (strlcpy(dt_path, buf, sizeof(dt_path)) > sizeof(dt_path)) {
        free(buf);
        return merr(ENAMETOOLONG);
    }

    yc.yaml_indent = 0;
    yc.yaml_offset = pathsz;
    yc.yaml_emit = yaml_realloc_buf;
    yc.yaml_buf_sz = bufsz;
    yc.yaml_buf = buf;

    if (dt_iterate_cmd(DT_OP_EMIT, dt_path, &dip, 0, fld, val) > 0)
        rest_write_safe(info->resp_fd, yc.yaml_buf + pathsz, yc.yaml_offset - pathsz);

    /* If the yaml buf grew then try to update dt_rest_get_bufsz
     * so that we are more likely to allocate a sufficiently sized
     * buffer the next time we are called.
     */
    bufsz = rest_dt_get_bufsz;
    if (yc.yaml_buf_sz > bufsz)
        atomic_cas(&rest_dt_get_bufsz, bufsz, yc.yaml_buf_sz);

    free(yc.yaml_buf);

    return 0;
}
