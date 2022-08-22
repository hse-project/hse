/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/hse.h>
#include <hse/flags.h>
#include <hse/experimental.h>

#include <hse/logging/logging.h>
#include <hse/error/merr.h>
#include <hse_util/event_counter.h>
#include <hse_util/fmt.h>

#include <hse_util/rest_api.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/kvset_view.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/cn_tree_view.h>
#include <hse_ikvdb/kvset_view.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/csched.h>

#include <cjson/cJSON_Utils.h>

#include "kvdb_rest.h"
#include "kvdb_kvs.h"

/* The yaml_emit() hook is called from yaml API functions
 * when the output buffer reaches 75% of maximum size.
 */
static void
kvdb_rest_yaml_emit(struct yaml_context *yc)
{
    if (yc->yaml_priv && yc->yaml_offset > 0) {
        struct conn_info *info = yc->yaml_priv;
        ssize_t cc;

        cc = rest_write_safe(info->resp_fd, yc->yaml_buf, yc->yaml_offset);
        if (cc != yc->yaml_offset) {
            merr_t err = merr(errno);

            log_errx("rest client short write (%ld < %zu)",
                     err, cc, yc->yaml_offset);

            yc->yaml_priv = NULL;
        }

        yc->yaml_offset = 0;
    }
}

/*---------------------------------------------------------------
 * rest: get handler for kvdb
 */
static merr_t
get_kvs_list(struct ikvdb *ikvdb, struct yaml_context *yc)
{
    char **kvs_list;
    size_t kvs_cnt;
    int    i;
    merr_t err;

    err = ikvdb_kvs_names_get(ikvdb, &kvs_cnt, &kvs_list);
    if (ev(err))
        return err;

    yaml_start_element_type(yc, "kvs_list");

    for (i = 0; i < kvs_cnt; i++)
        yaml_list_fmt(yc, "%s", kvs_list[i]);

    yaml_end_element_type(yc);
    yc->yaml_emit(yc);

    ikvdb_kvs_names_free(ikvdb, kvs_list);

    return 0;
}

static merr_t
rest_kvdb_get(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    struct yaml_context yc = {
        .yaml_buf = info->buf,
        .yaml_buf_sz = info->buf_sz,
        .yaml_emit = kvdb_rest_yaml_emit,
        .yaml_priv = info,
    };
    struct ikvdb *ikvdb = context;

    /* verify that the request was exact */
    if (ev(strcmp(path, url) != 0))
        return merr(E2BIG);

    return get_kvs_list(ikvdb, &yc);
}

static merr_t
rest_kvdb_home_get(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    char          buf[PATH_MAX + 2];
    struct ikvdb *kvdb = context;
    const char *  home = ikvdb_home(kvdb);
    int           n HSE_MAYBE_UNUSED;

    n = snprintf(buf, sizeof(buf), "\"%s\"", home);
    assert(n >= 0 && n < sizeof(buf));

    if (write(info->resp_fd, buf, strlen(buf)) == -1)
        return merr(errno);

    return 0;
}

static merr_t
rest_kvdb_param_get(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    merr_t        err = 0;
    struct ikvdb *kvdb = context;

    /* Check from single parameter or all parameters */
    if (strcmp(path, url)) {
        size_t      needed_sz;
        char *      tmp;
        size_t      buf_sz = 128;
        const char *param = path + strlen(url) + 1; /* move past the final '/' */
        char *      buf = malloc(buf_sz);

        if (!buf)
            return merr(ENOMEM);

        err = ikvdb_param_get(kvdb, param, buf, buf_sz, &needed_sz);
        if (needed_sz >= buf_sz && !err) {
            buf_sz = needed_sz + 1;
            tmp = realloc(buf, buf_sz);
            if (!tmp)
                return merr(ENOMEM);

            buf = tmp;

            err = ikvdb_param_get(kvdb, param, buf, buf_sz, NULL);
        }

        if (!err && write(info->resp_fd, buf, strnlen(buf, buf_sz)) == -1)
            err = merr(errno);

        free(buf);
    } else {
        char * str;
        cJSON *root = kvdb_rparams_to_json(ikvdb_rparams(kvdb));
        if (!root)
            return merr(ENOMEM);

        str = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        if (!str)
            return merr(ENOMEM);

        if (!err && write(info->resp_fd, str, strlen(str)) == -1)
            err = merr(errno);

        cJSON_free(str);
    }

    return err;
}

static merr_t
rest_kvdb_param_put(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    const char *  param;
    struct ikvdb *kvdb = context;
    const bool    has_param = strcmp(path, url);

    /* Check for case when no parameter is specified, /kvdb/0/params */
    if (!has_param)
        return merr(EINVAL);

    param = path + strlen(url) + 1;

    return kvdb_rparams_set(ikvdb_rparams(kvdb), param, info->data);
}

static merr_t
rest_kvs_param_get(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    merr_t          err = 0;
    struct hse_kvs *kvs = context;

    /* Check from single parameter or all parameters */
    if (strcmp(path, url)) {
        size_t      needed_sz;
        char *      tmp;
        size_t      buf_sz = 128;
        const char *param = path + strlen(url) + 1; /* move past the final '/' */
        char *      buf = malloc(buf_sz);

        if (!buf)
            return merr(ENOMEM);

        err = ikvdb_kvs_param_get(kvs, param, buf, buf_sz, &needed_sz);
        if (needed_sz >= buf_sz && !err) {
            buf_sz = needed_sz + 1;
            tmp = realloc(buf, buf_sz);
            if (!tmp)
                return merr(ENOMEM);

            buf = tmp;

            err = ikvdb_kvs_param_get(kvs, param, buf, buf_sz, NULL);
        }

        if (!err && write(info->resp_fd, buf, strnlen(buf, buf_sz)) == -1)
            err = merr(errno);

        free(buf);
    } else {
        char * str;
        cJSON *merged, *cp_json, *rp_json;

        cp_json = kvs_cparams_to_json(((struct kvdb_kvs *)kvs)->kk_cparams);
        if (!cp_json)
            return merr(ENOMEM);

        rp_json = kvs_rparams_to_json(&((struct kvdb_kvs *)kvs)->kk_ikvs->ikv_rp);
        if (!rp_json) {
            cJSON_Delete(cp_json);
            return merr(ENOMEM);
        }

        merged = cJSONUtils_MergePatchCaseSensitive(cp_json, rp_json);
        if (!merged) {
            cJSON_Delete(cp_json);
            cJSON_Delete(rp_json);
            return merr(ENOMEM);
        }

        str = cJSON_PrintUnformatted(merged);
        cJSON_Delete(merged);
        cJSON_Delete(rp_json);
        if (!str) {
            return merr(ENOMEM);
        }

        if (!err && write(info->resp_fd, str, strlen(str)) == -1)
            err = merr(errno);

        cJSON_free(str);
    }

    return err;
}

static merr_t
rest_kvs_param_put(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    const char *     param;
    struct kvdb_kvs *kvs = context;
    const bool       has_param = strcmp(path, url);

    /* Check for case when no parameter is specified, /kvdb/0/kvs/1/params */
    if (!has_param)
        return merr(EINVAL);

    param = path + strlen(url) + 1;

    return kvs_rparams_set(&kvs->kk_ikvs->ikv_rp, param, info->data);
}

static merr_t
rest_kvdb_mclass_info_get(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    merr_t                 err = 0;
    enum hse_mclass        mclass = HSE_MCLASS_INVALID;
    struct hse_mclass_info mc_info;
    cJSON *                root;
    char *                 str;

    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        if (strstr(path, hse_mclass_name_get(i))) {
            mclass = (enum hse_mclass)i;
            break;
        }
    }

    assert(mclass != HSE_MCLASS_INVALID);

    err = ikvdb_mclass_info_get((struct ikvdb *)context, mclass, &mc_info);
    if (err)
        return err;

    root = cJSON_CreateObject();
    if (!root)
        return merr(ENOMEM);

    if (!cJSON_AddNumberToObject(root, "allocated_bytes", mc_info.mi_allocated_bytes)) {
        err = merr(ENOMEM);
        goto out;
    }

    if (!cJSON_AddNumberToObject(root, "used_bytes", mc_info.mi_used_bytes)) {
        err = merr(ENOMEM);
        goto out;
    }

    if (!cJSON_AddStringToObject(root, "path", mc_info.mi_path)) {
        err = merr(ENOMEM);
        goto out;
    }

    str = cJSON_PrintUnformatted(root);
    if (!str) {
        err = merr(ENOMEM);
        goto out;
    }

    if (!err && write(info->resp_fd, str, strlen(str)) == -1)
        err = merr(errno);

    cJSON_free(str);

out:
    cJSON_Delete(root);

    return err;
}

static merr_t
rest_kvdb_compact_request(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    struct ikvdb *  ikvdb = context;
    int             flags;
    struct rest_kv *kv;
    const char *    p = path + strlen(url);
    const char *    action;

    if (ev(*p == 0))
        return merr(EINVAL);

    action = p + 1;

    /* process arguments */
    flags = 0;
    kv = rest_kv_next(iter);
    if (!kv) {
        flags = HSE_KVDB_COMPACT_SAMP_LWM;
    } else if (strcmp(kv->key, "policy") == 0) {
        if (strcmp(kv->value, "samp_lwm") == 0)
            flags = HSE_KVDB_COMPACT_SAMP_LWM;
        else if (strcmp(kv->value, "cancel") == 0)
            flags = HSE_KVDB_COMPACT_CANCEL;
    }

    /* process command */
    if (strcmp(action, "request"))
        return merr(EINVAL);

    ikvdb_compact(ikvdb, flags);

    return 0;
}

static merr_t
rest_kvdb_compact_status_get(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    struct ikvdb *                 ikvdb = context;
    struct hse_kvdb_compact_status status = { 0 };
    const char *                   p = path + strlen(url);
    const char *                   action;
    size_t                         b, buf_off;
    char *                         buf = info->buf;
    size_t                         bufsz = info->buf_sz;

    if (ev(*p == 0))
        return merr(EINVAL);

    action = p + 1;

    if (ev(strcmp(action, "status")))
        return merr(EINVAL);

    ikvdb_compact_status_get(ikvdb, &status);

    buf_off = 0;
    b = snprintf_append(buf, bufsz, &buf_off, "status:\n");
    b += snprintf_append(buf, bufsz, &buf_off, "samp_lwm_pct: %u\n", status.kvcs_samp_lwm);
    b += snprintf_append(buf, bufsz, &buf_off, "samp_hwm_pct: %u\n", status.kvcs_samp_hwm);
    b += snprintf_append(buf, bufsz, &buf_off, "samp_curr_pct: %u\n", status.kvcs_samp_curr);
    b += snprintf_append(buf, bufsz, &buf_off, "request_active: %u\n", status.kvcs_active);
    b += snprintf_append(buf, bufsz, &buf_off, "request_canceled: %u\n", status.kvcs_canceled);

    if (write(info->resp_fd, buf, b) != b)
        return merr(EIO);

    return 0;
}

merr_t
kvdb_rest_register(struct ikvdb *kvdb)
{
    merr_t status, err = 0;

    if (ev(!kvdb))
        return merr(EINVAL);

    status =
        rest_url_register(kvdb, URL_FLAG_EXACT, rest_kvdb_get, 0, "kvdb/%s", ikvdb_alias(kvdb));
    if (ev(status) && !err)
        err = status;

    status = rest_url_register(
        kvdb, URL_FLAG_EXACT, rest_kvdb_home_get, NULL, "kvdb/%s/home", ikvdb_alias(kvdb));
    if (ev(status) && !err)
        err = status;

    status = rest_url_register(
        kvdb, 0, rest_kvdb_param_get, rest_kvdb_param_put, "kvdb/%s/params", ikvdb_alias(kvdb));
    if (ev(status) && !err)
        err = status;

    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        status = rest_url_register(kvdb, URL_FLAG_EXACT, rest_kvdb_mclass_info_get, NULL,
            "kvdb/%s/mclass/%s/info", ikvdb_alias(kvdb), hse_mclass_name_get(i));
        if (ev(status) && !err)
            err = status;
    }

    status = rest_url_register(
        kvdb,
        URL_FLAG_NONE,
        rest_kvdb_compact_status_get,
        rest_kvdb_compact_request,
        "kvdb/%s/compact",
        ikvdb_alias(kvdb));

    return err;
}

merr_t
kvdb_rest_deregister(struct ikvdb *const kvdb)
{
    return rest_url_deregister("kvdb/%s", ikvdb_alias(kvdb));
}

/*---------------------------------------------------------------
 * rest: get handler for kvs
 */
enum elem_type {
    TYPE_TREE   = 't',
    TYPE_NODE   = 'n',
    TYPE_KVSET  = 'k',
};

struct ctx {
    struct yaml_context *yc;

    bool yaml;      /* generate yaml if true  */
    bool blkids;    /* print block ids if true */
    bool nodesonly; /* skip kvsets if true */
    bool human;     /* show large values in human-readable form */
    int  hdrsmax;   /* max headers to emit */

    const int *colwidthv; /* vector of column widths for tabular mode */

    const char *kvsname;
    uint64_t    cnid;

    uint eklen;
    uint eklen_max;
    char ekbuf[sizeof((struct kvset_view *)0)->ekbuf * 3 + 4];

    struct kvset_metrics total;
    struct kvset_metrics node;

    enum elem_type prev_elem;

    /* per node */
    uint64_t node_nodeid;
    uint32_t node_hblks;
    uint32_t node_kblks;
    uint32_t node_vblks;
    uint64_t node_dgen;

    /* per kvset */
    uint64_t kvset_nodeid;
    u64 kvset_dgen;
    u32 kvset_idx;
    u32 num_kblks;
    u32 num_vblks;

    /* per tree */
    u32 tot_kvsets;
    u32 tot_nodes;
    u32 tot_hblks;
    u32 tot_kblks;
    u32 tot_vblks;
    u64 tree_dgen;
};

enum mb_type { TYPE_KBLK, TYPE_VBLK };

static void
yc_snprintf(struct yaml_context *yc, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (yc->yaml_buf_sz - yc->yaml_offset < 4096)
        yc->yaml_emit(yc);

    va_start(ap, fmt);
    n = vsnprintf(yc->yaml_buf + yc->yaml_offset, yc->yaml_buf_sz - yc->yaml_offset, fmt, ap);
    va_end(ap);

    yc->yaml_offset += (n > 0) ? n : 0;

}

static void
print_blkids(struct ctx *ctx, enum mb_type type, struct kvset *kvset)
{
    struct yaml_context *yc = ctx->yc;
    uint32_t n, i;

    switch (type) {
    case TYPE_KBLK:
        n = kvset_get_num_kblocks(kvset);
        if (ctx->yaml) {
            for (i = 0; i < n; ++i)
                yaml_list_fmt(yc, "0x%lx", kvset_get_nth_kblock_id(kvset, i));

            yaml_end_element(yc);
        } else {
            yc_snprintf(yc, " /");

            for (i = 0; i < n; ++i)
                yc_snprintf(yc, " 0x%lx", kvset_get_nth_kblock_id(kvset, i));
        }
        break;

    case TYPE_VBLK:
        n = kvset_get_num_vblocks(kvset);
        if (ctx->yaml) {
            for (i = 0; i < n; ++i)
                yaml_list_fmt(yc, "0x%lx", kvset_get_nth_vblock_id(kvset, i));

            yaml_end_element(yc);
        } else {
            yc_snprintf(yc, " /");

            for (i = 0; i < n; ++i)
                yc_snprintf(yc, " 0x%lx", kvset_get_nth_vblock_id(kvset, i));
        }
        break;
    }
}

static const char *hdrfmt =
    "\n# NODE  IDX"
    " %5s %5s %*s %*s %*s %*s %*s %*s %5s %5s %5s %5s %7s %3s %4s  %-s\n";

static const char *unitfmt =
    " %5u %5lu %*s %*s %*s %*s %*s %*s %5d %5d %5d %5u %7s %3u %4u  %-s";

static void
print_hdr(struct ctx *ctx, const char *append)
{
    const int *width = ctx->colwidthv;

    if (--ctx->hdrsmax < 0)
        return;

    yc_snprintf(ctx->yc, hdrfmt,
                "DGEN", "COMP",
                width[0], "KEYS",
                width[1], "TOMBS",
                width[2], "PTOMBS",
                width[3], "HLEN",
                width[4], "KLEN",
                width[5], "VLEN",
                "HBLK", "KBLK", "VBLK",
                "VGRP", "RULE",
                "ID", "EKL",
                append);
}

static void
u64_to_human(char *buf, size_t bufsz, uint64_t val, uint64_t thresh)
{
    if (val >= thresh) {
        const char *sep = "\0kmgtpezy";

        val *= 10;

        while (val >= thresh) {
            val /= 1000;
            ++sep;
        }

        snprintf(buf, bufsz, "%5.1lf%c", val / 10.0, *sep);
    } else {
        u64_to_string(buf, bufsz, val);
    }
}

static void
print_unit(
    struct ctx                 *ctx,
    enum elem_type              type,
    u64                         dgen,
    const struct kvset_metrics *m,
    const char                 *trailer,
    int                         nkvsets,
    int                         nhblks,
    int                         nkblks,
    int                         nvblks)
{
    char keysbuf[32], tombsbuf[32], ptombsbuf[32];
    char hlenbuf[32], klenbuf[32], vlenbuf[32];
    struct yaml_context *yc = ctx->yc;
    uint64_t thresh = ctx->human ? 10000 : UINT64_MAX;

    u64_to_human(keysbuf, sizeof(keysbuf), m->num_keys, thresh);
    u64_to_human(tombsbuf, sizeof(tombsbuf), m->num_tombstones, thresh);
    u64_to_human(ptombsbuf, sizeof(ptombsbuf), m->nptombs, thresh);
    u64_to_human(hlenbuf, sizeof(hlenbuf), m->header_bytes, thresh);
    u64_to_human(klenbuf, sizeof(klenbuf), m->tot_key_bytes, thresh);
    u64_to_human(vlenbuf, sizeof(vlenbuf), m->tot_val_bytes, thresh);

    if (ctx->yaml) {
        yaml_field_fmt_u64(yc, "dgen", dgen);
        yaml_field_fmt(yc, "compc", "%u", m->compc);
        yaml_element_field(yc, "keys", keysbuf);
        yaml_element_field(yc, "tombs", tombsbuf);
        yaml_element_field(yc, "ptombs", ptombsbuf);

        yaml_element_field(yc, "hlen", hlenbuf);
        yaml_element_field(yc, "klen", klenbuf);
        yaml_element_field(yc, "vlen", vlenbuf);

        yaml_field_fmt(yc, "hblks", "%d", nhblks);
        yaml_field_fmt(yc, "kblks", "%d", nkblks);
        yaml_field_fmt(yc, "vblks", "%d", nvblks);

        yaml_field_fmt(yc, "vgroups", "%u", m->vgroups);

        if (type == TYPE_KVSET)
            yaml_field_fmt(yc, "rule", "%s", cn_rule2str(m->rule));
        else
            yaml_field_fmt(yc, "kvsets", "%d", nkvsets);
    } else {
        const int *width = ctx->colwidthv;

        yc_snprintf(yc, unitfmt,
                    dgen, m->compc,
                    width[0], keysbuf,
                    width[1], tombsbuf,
                    width[2], ptombsbuf,
                    width[3], hlenbuf,
                    width[4], klenbuf,
                    width[5], vlenbuf,
                    nhblks, nkblks, nvblks,
                    m->vgroups,
                    (type == TYPE_KVSET) ? cn_rule2str(m->rule) : "-",
                    ctx->cnid,
                    ctx->eklen,
                    trailer);
    }
}

static void
print_elem(
    struct ctx           *ctx,
    enum elem_type        type,
    struct kvset_metrics *m,
    struct kvset *        kvset)
{
    struct yaml_context *yc = ctx->yc;

    switch (type) {
    case TYPE_KVSET:
        if (ctx->prev_elem == TYPE_NODE) {
            if (ctx->yaml) {
                yaml_start_element(yc, "loc", "");
                yc->yaml_indent++;
                yaml_field_fmt(yc, "nodeid", "%lu", ctx->node_nodeid);
                yc->yaml_indent--;
            } else {
                print_hdr(ctx, "EKHEX");
            }

            ctx->prev_elem = TYPE_KVSET;
        }

        if (ctx->nodesonly)
            break;

        if (ctx->yaml) {
            char idxbuf[16];

            if (ctx->kvset_idx == 0)
                yaml_start_element_type(yc, "kvsets");

            snprintf(idxbuf, sizeof(idxbuf), "%u", ctx->kvset_idx++);
            yaml_start_element(yc, "index", idxbuf);
        } else {
            yc_snprintf(yc, "%c %4lu %4u", TYPE_KVSET, ctx->kvset_nodeid, ctx->kvset_idx++);
        }

        print_unit(ctx, TYPE_KVSET, ctx->kvset_dgen, m, "-",
                   -1, 1, ctx->num_kblks, ctx->num_vblks);

        if (ctx->yaml) {
            if (ctx->blkids) {
                yaml_field_fmt(yc, "hblkid", "0x%lx",
                               kvset_get_hblock_id(kvset));

                yaml_start_element_type(yc, "kblkids");
                print_blkids(ctx, TYPE_KBLK, kvset);
                yaml_end_element_type(yc);

                yaml_start_element_type(yc, "vblkids");
                print_blkids(ctx, TYPE_VBLK, kvset);
                yaml_end_element_type(yc);
            }

            yaml_end_element(yc); /* index */
        } else {
            if (ctx->blkids) {
                yc_snprintf(yc, " %lx", kvset_get_hblock_id(kvset));
                print_blkids(ctx, TYPE_KBLK, kvset);
                print_blkids(ctx, TYPE_VBLK, kvset);
            }

            yc_snprintf(yc, "\n");
        }
        break;

    case TYPE_NODE:
        if (ctx->prev_elem == TYPE_NODE)
            break;

        if (ctx->prev_elem == TYPE_KVSET) {
            if (ctx->yaml)
                yaml_end_element_type(yc); /* kvsets */

            ctx->prev_elem = TYPE_NODE;
        }

        if ((m->num_keys | m->num_tombstones | m->nptombs) == 0)
            break;

        if (ctx->yaml) {
            yaml_start_element_type(yc, "info");
        } else {
            yc_snprintf(yc, "%c %4lu %4u", TYPE_NODE, ctx->kvset_nodeid, ctx->kvset_idx);
        }

        print_unit(ctx, TYPE_NODE, ctx->node_dgen, m, (ctx->eklen > 0) ? ctx->ekbuf : "-",
                   ctx->kvset_idx, ctx->node_hblks, ctx->node_kblks, ctx->node_vblks);

        if (ctx->yaml) {
            yaml_end_element(yc);
            yaml_end_element_type(yc);
        } else {
            yc_snprintf(yc, "\n");
        }

        /* Each node resets the kvset_idx */
        ctx->kvset_idx = 0;
        break;

    default:
        ev_warn(1);
        break;
    }
}

static int
print_tree(struct ctx *ctx, struct kvset_view *v)
{
    struct kvset_metrics km;
    struct kvset *kvset;

    /* A null kvset is the start of a new node.
     */
    kvset = v->kvset;
    if (!kvset) {
        if (ctx->tot_nodes > 0)
            print_elem(ctx, TYPE_NODE, &ctx->node, NULL);

        memset(&ctx->node, 0, sizeof(ctx->node));
        ctx->node_hblks = 0;
        ctx->node_kblks = 0;
        ctx->node_vblks = 0;
        ctx->node_dgen = 0;
        ++ctx->tot_nodes;

        ctx->node_nodeid = v->nodeid;
        ctx->eklen = v->eklen;
        if (ctx->eklen > 0)
            fmt_hexp(ctx->ekbuf, sizeof(ctx->ekbuf), v->ekbuf,
                     min_t(size_t, sizeof(v->ekbuf), v->eklen), "0x", 2, ".", "");

        if (ctx->eklen > ctx->eklen_max)
            ctx->eklen_max = ctx->eklen;

        return 0;
    }

    kvset_get_metrics(kvset, &km);

    ++ctx->tot_kvsets;
    ctx->tot_hblks++;
    ctx->node_hblks++;
    ctx->num_kblks = kvset_get_num_kblocks(kvset);
    ctx->tot_kblks += ctx->num_kblks;
    ctx->node_kblks += ctx->num_kblks;
    ctx->num_vblks = kvset_get_num_vblocks(kvset);
    ctx->tot_vblks += ctx->num_vblks;
    ctx->node_vblks += ctx->num_vblks;

    ctx->kvset_nodeid = kvset_get_nodeid(kvset);

    ctx->kvset_dgen = kvset_get_dgen(kvset);
    if (ctx->kvset_dgen > ctx->node_dgen)
        ctx->node_dgen = ctx->kvset_dgen;
    if (ctx->kvset_dgen > ctx->tree_dgen)
        ctx->tree_dgen = ctx->kvset_dgen;

    ctx->node.num_keys += km.num_keys;
    ctx->node.num_tombstones += km.num_tombstones;
    ctx->node.nptombs += km.nptombs;
    ctx->node.num_kblocks += km.num_kblocks;
    ctx->node.num_vblocks += km.num_vblocks;
    ctx->node.header_bytes += km.header_bytes;
    ctx->node.tot_key_bytes += km.tot_key_bytes;
    ctx->node.tot_val_bytes += km.tot_val_bytes;
    ctx->node.vgroups += km.vgroups;
    if (km.compc > ctx->node.compc)
        ctx->node.compc = km.compc;

    ctx->total.num_keys += km.num_keys;
    ctx->total.num_tombstones += km.num_tombstones;
    ctx->total.nptombs += km.nptombs;
    ctx->total.num_kblocks += km.num_kblocks;
    ctx->total.num_vblocks += km.num_vblocks;
    ctx->total.header_bytes += km.header_bytes;
    ctx->total.tot_key_bytes += km.tot_key_bytes;
    ctx->total.tot_val_bytes += km.tot_val_bytes;
    ctx->total.vgroups += km.vgroups;
    if (km.compc > ctx->total.compc)
        ctx->total.compc = km.compc;

    print_elem(ctx, TYPE_KVSET, &km, kvset);

    return 0;
}

static merr_t
kvs_rest_query_tree_impl(
    struct kvdb_kvs *kvs,
    struct yaml_context *yc,
    bool blkids,
    bool nodesonly,
    bool tabular,
    bool human)
{
    struct table *tree_view;
    struct ctx ctx;
    struct cn *cn;
    merr_t err;

    cn = kvs_cn(kvs->kk_ikvs);
    if (ev(!cn))
        return merr(EINVAL);

    memset(&ctx, 0, sizeof(ctx));
    ctx.yc = yc;
    ctx.yaml = !tabular;
    ctx.blkids = blkids;
    ctx.nodesonly = nodesonly;
    ctx.human = human;
    ctx.hdrsmax = nodesonly ? 1 : INT_MAX;
    ctx.cnid = kvs->kk_cnid;

    if (human) {
        static const int kvs_rest_colwidthv_human[] = { 7, 7, 7, 7, 7, 7 };

        ctx.colwidthv = kvs_rest_colwidthv_human;
    } else {
        static const int kvs_rest_colwidthv_default[] = { 11, 6, 7, 9, 12, 14 };

        ctx.colwidthv = kvs_rest_colwidthv_default;
    }

    ctx.node_nodeid = UINT64_MAX;
    ctx.prev_elem = TYPE_NODE;

    if (ctx.yaml) {
        yaml_start_element_type(yc, "nodes");
    }

    err = cn_tree_view_create(cn, &tree_view);
    if (ev(err))
        return err;

    for (size_t i = 0; i < table_len(tree_view); ++i) {
        struct kvset_view *v = table_at(tree_view, i);
        int rc;

        rc = print_tree(&ctx, v);
        if (rc)
            break;
    }

    print_elem(&ctx, TYPE_NODE, &ctx.node, NULL);

    cn_tree_view_destroy(tree_view);

    if (ctx.yaml) {
        yaml_end_element_type(yc); /* nodes */
        yaml_start_element_type(yc, "info");
    } else {
        print_hdr(&ctx, "NAME");
        yc_snprintf(yc, "%c %4u %4u", TYPE_TREE, ctx.tot_nodes, ctx.tot_kvsets);
    }

    ctx.eklen = ctx.eklen_max;

    print_unit(&ctx, TYPE_TREE, ctx.tree_dgen, &ctx.total, kvs->kk_name,
               ctx.tot_kvsets, ctx.tot_hblks, ctx.tot_kblks, ctx.tot_vblks);

    if (ctx.yaml) {
        yaml_field_fmt(yc, "nodes", "%u", ctx.tot_nodes);
        yaml_field_fmt(yc, "cnid", "%lu", kvs->kk_cnid);
        yaml_field_fmt(yc, "name", "%s", kvs->kk_name);
        yaml_field_fmt(yc, "open", "yes");

        yaml_end_element(yc);
        yaml_end_element(yc);
        yaml_end_element_type(yc); /* info */
    } else {
        yc_snprintf(yc, "\n");
    }

    return 0;
}

merr_t
kvs_rest_query_tree(
    struct kvdb_kvs     *kvs,
    struct yaml_context *yc,
    bool                 blkids,
    bool                 nodesonly)
{
    return kvs_rest_query_tree_impl(kvs, yc, blkids, nodesonly, false, false);
}

bool
rest_queryval_to_bool(const char *val, bool *result)
{
    const char tab[] = "&t&f&y&n&true&false&yes&no&";
    char *begin, *end;

    if (!val) {
        *result = true;
        return true;
    }

    while (isspace(*val))
        ++val;

    if (isdigit(*val)) {
        unsigned long n;

        errno = 0;
        n = strtoul(val, &end, 0);
        if (errno || (end && *end))
            return false;

        *result = !!n;
        return true;
    }

    /* If val exactly matches any substring in tab[]
     * then it can be converted to a bool.
     */
    begin = strcasestr(tab, val);
    if (begin && begin[-1] == tab[0]) {
        end = strchr(begin, tab[0]);
        if (strncmp(begin, val, end - begin) == 0) {
            *result = !strchr("fFnN", *begin);
            return true;
        }
    }

    return false;
}

static merr_t
rest_kvs_tree(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    static atomic_ulong rest_kvs_tree_bufsz = 128 * 1024;
    struct yaml_context yc = {
        .yaml_buf = info->buf,
        .yaml_buf_sz = info->buf_sz,
        .yaml_emit = kvdb_rest_yaml_emit,
        .yaml_priv = info,
    };
    struct kvdb_kvs *kvs = context;
    struct rest_kv *kv;
    bool nodesonly = false;
    bool tabular = false;
    bool blkids = false;
    bool human = false;
    bool help = false;

    if (strcmp(path, url) != 0)
        return merr(E2BIG);

    /* HSE_REVISIT: It is not safe to make a ref out of thin air.
     * The ref should be obtained when this endpoint is registered.
     */
    atomic_inc(&kvs->kk_refcnt);

    if (!kvs->kk_ikvs) {
        /* kvs is closed */
        yaml_start_element_type(&yc, "info");
        yaml_field_fmt(&yc, "cnid", "%lu", kvs->kk_cnid);
        yaml_field_fmt(&yc, "name", "%s", kvs->kk_name);
        yaml_field_fmt(&yc, "open", "no");
        yaml_end_element(&yc);
        yaml_end_element_type(&yc); /* info */
        yc.yaml_emit(&yc);

        atomic_dec(&kvs->kk_refcnt);
        return 0;
    }

    while (( kv = rest_kv_next(iter) )) {
        if (strcasecmp(kv->key, "tabular") == 0) {
            if (rest_queryval_to_bool(kv->value, &tabular))
                continue;
        }
        else if (strcasecmp(kv->key, "blkids") == 0) {
            if (rest_queryval_to_bool(kv->value, &blkids))
                continue;
        }
        else if (strcasecmp(kv->key, "human") == 0) {
            if (rest_queryval_to_bool(kv->value, &human)) {
                continue;
            }
        }
        else if (strcasecmp(kv->key, "nodesonly") == 0) {
            if (rest_queryval_to_bool(kv->value, &nodesonly))
                continue;
        }
        else if (strcasecmp(kv->key, "help") == 0) {
            rest_queryval_to_bool(kv->value, &help);
        }

        if (help) {
            yc_snprintf(&yc, "\nURI query options:\n");
            yc_snprintf(&yc, "  NAME       TYPE  DESCRIPTION:\n");
            yc_snprintf(&yc, "  blkids     bool  include all HKV block IDs\n");
            yc_snprintf(&yc, "  help       bool  this list\n");
            yc_snprintf(&yc, "  human      bool  suffix large values with SI prefixes\n");
            yc_snprintf(&yc, "  nodesonly  bool  skip kvsets\n");
            yc_snprintf(&yc, "  tabular    bool  output in tabular format (default yaml)\n");
        } else {
            yc_snprintf(&yc, "\ninvalid URI query: %s%c%s, use ?help for more information\n",
                        kv->key, kv->value ? '=' : ' ', kv->value ? kv->value : "null");
        }
        yc.yaml_emit(&yc);

        atomic_dec(&kvs->kk_refcnt);

        return help ? 0 : merr(EINVAL);
    }

    /* Here we try to allocate a private buffer that yaml_realloc_buf()
     * can realloc() as necessary.  This will allow us to emit the full
     * yaml document in one write() after we have released all the
     * kvsets in the tree view (see kvs_rest_query_tree()).
     */
    yc.yaml_buf_sz = rest_kvs_tree_bufsz;
    yc.yaml_offset = 0;

    yc.yaml_buf = malloc(yc.yaml_buf_sz);
    if (yc.yaml_buf) {
        yc.yaml_emit = yaml_realloc_buf;
    } else {
        yc.yaml_buf_sz = info->buf_sz;
        yc.yaml_buf = info->buf;
    }

    kvs_rest_query_tree_impl(kvs, &yc, blkids, nodesonly, tabular, human);

    kvdb_rest_yaml_emit(&yc);

    /* If the yaml buf grew then try to update rest_kvs_tree_bufsz
     * so that we are more likely to allocate a sufficiently sized
     * buffer the next time we are called.
     */
    if (yc.yaml_emit == yaml_realloc_buf) {
        size_t bufsz = rest_kvs_tree_bufsz;

        if (yc.yaml_buf_sz > bufsz)
            atomic_cas(&rest_kvs_tree_bufsz, bufsz, yc.yaml_buf_sz);

        free(yc.yaml_buf);
    }

    atomic_dec(&kvs->kk_refcnt);

    return 0;
}

merr_t
kvs_rest_register(struct ikvdb *const kvdb, const char *kvs_name, struct kvdb_kvs *kvs)
{
    merr_t err = 0;
    merr_t status;

    if (ev(!kvs_name || !kvs))
        return merr(EINVAL);

    status = rest_url_register(
        kvs,
        0,
        rest_kvs_param_get,
        rest_kvs_param_put,
        "kvdb/%s/kvs/%s/params",
        ikvdb_alias(kvdb),
        kvs_name);
    if (ev(status) && !err)
        err = status;

    status = rest_url_register(
        kvs,
        URL_FLAG_EXACT,
        rest_kvs_tree,
        0,
        "kvdb/%s/kvs/%s/cn/tree",
        ikvdb_alias(kvdb),
        kvs_name);
    if (ev(status) && !err)
        err = status;

    return err;
}

merr_t
kvs_rest_deregister(struct ikvdb *const kvdb, const char *kvs_name)
{
    merr_t err = 0;
    merr_t status;

    if (ev(!kvs_name))
        return merr(EINVAL);

    status = rest_url_deregister("kvdb/%s/kvs/%s/cn/tree", ikvdb_alias(kvdb), kvs_name);

    if (ev(status) && !err)
        err = status;

    return err;
}
