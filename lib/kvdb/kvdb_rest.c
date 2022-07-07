/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/hse.h>
#include <hse/flags.h>
#include <hse/experimental.h>

#include <hse_util/logging.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>

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

            log_errx("short rest client write (%ld < %zu): @@e",
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
        yaml_list_fmt(yc, kvs_list[i]);

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
        assert(merged);

        str = cJSON_PrintUnformatted(merged);
        cJSON_Delete(merged);
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
    TYPE_NODE,
    TYPE_KVSET,
    TYPE_BEGIN = TYPE_NODE,
};

struct ctx {
    struct yaml_context *yc;
    bool                 list; /* whether or not to print block ids */

    struct kvset_metrics total;
    struct kvset_metrics node;

    enum elem_type prev_elem;

    /* per node */
    struct cn_node_loc node_loc; /* cached loc */
    u32                node_hblks;
    u32                node_kblks;
    u32                node_vblks;
    u64                node_dgen;

    /* per kvset */
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
print_ids(struct kvset *kvset, enum mb_type type, struct yaml_context *yc)
{
    int i, n = 0;

    switch (type) {
    case TYPE_KBLK:
        n = kvset_get_num_kblocks(kvset);
        for (i = 0; i < n; ++i)
            yaml_list_fmt(yc, "0x%lx", kvset_get_nth_kblock_id(kvset, i));
        break;

    case TYPE_VBLK:
        n = kvset_get_num_vblocks(kvset);
        for (i = 0; i < n; ++i)
            yaml_list_fmt(yc, "0x%lx", kvset_get_nth_vblock_id(kvset, i));
        break;
    }

    if (n > 0)
        yaml_end_element(yc);
}

static void
print_unit(
    int                  type,
    u64                  dgen,
    uint                 compc,
    uint                 comp_rule,
    u32                  vgroups,
    u64                  nkeys,
    u64                  ntombs,
    u64                  nptombs,
    u64                  hlen,
    u64                  klen,
    u64                  vlen,
    int                  nkvsets,
    int                  nhblks,
    int                  nkblks,
    int                  nvblks,
    struct yaml_context *yc)
{
    if (type == 'k')
        yaml_field_fmt(yc, "compc", "%u", compc);

    yaml_field_fmt_u64(yc, "dgen", dgen);
    yaml_field_fmt_u64(yc, "keys", nkeys);
    yaml_field_fmt_u64(yc, "tombs", ntombs);
    yaml_field_fmt_u64(yc, "ptombs", nptombs);

    yaml_field_fmt_u64(yc, "hlen", hlen);
    yaml_field_fmt_u64(yc, "klen", klen);
    yaml_field_fmt_u64(yc, "vlen", vlen);

    yaml_field_fmt(yc, "hblks", "%d", nhblks);
    yaml_field_fmt(yc, "kblks", "%d", nkblks);
    yaml_field_fmt(yc, "vblks", "%d", nvblks);

    if (nkvsets >= 0) {
        yaml_field_fmt(yc, "kvsets", "%d", nkvsets);
    } else {
        yaml_field_fmt(yc, "vgroups", "%u", vgroups);
    }

    if (type == 'k')
        yaml_field_fmt(yc, "rule", "%s", cn_comp_rule2str(comp_rule));
}

static void
print_elem(
    const char *          who,
    struct ctx *          ctx,
    struct kvset_metrics *m,
    struct cn_node_loc *  loc,
    struct kvset *        kvset)
{
    struct yaml_context *yc = ctx->yc;
    char idxbuf[16];

    if (ctx->prev_elem == TYPE_NODE) {
        /* This is the start of a new node */
        yaml_start_element(yc, "loc", "");
        yc->yaml_indent++;
        yaml_field_fmt(yc, "level", "%u", loc->node_level);
        yaml_field_fmt(yc, "offset", "%u", loc->node_offset);
        yc->yaml_indent--;
    }

    switch (who[0]) {
    case 'k':
        if (ctx->prev_elem == TYPE_NODE)
            yaml_start_element_type(yc, "kvsets");

        snprintf(idxbuf, sizeof(idxbuf), "%u", ctx->kvset_idx++);
        yaml_start_element(yc, "index", idxbuf);

        print_unit(
            'k',
            ctx->kvset_dgen,
            m->compc,
            m->comp_rule,
            m->vgroups,
            m->num_keys,
            m->num_tombstones,
            m->nptombs,
            m->header_bytes,
            m->tot_key_bytes,
            m->tot_val_bytes,
            -1,
            1, /* always one hblock */
            ctx->num_kblks,
            ctx->num_vblks,
            yc);

        if (ctx->list) {
            yaml_field_fmt(yc, "hblkid", "0x%lx",
                           kvset_get_hblock_id(kvset));

            yaml_start_element_type(yc, "kblkids");
            print_ids(kvset, TYPE_KBLK, yc);
            yaml_end_element_type(yc);

            yaml_start_element_type(yc, "vblkids");
            print_ids(kvset, TYPE_VBLK, yc);
            yaml_end_element_type(yc);
        }

        yaml_end_element(yc); /* index */

        ctx->prev_elem = TYPE_KVSET;
        break;

    case 'n':
        if (ctx->prev_elem == TYPE_KVSET)
            yaml_end_element_type(yc); /* kvsets */

        yaml_start_element_type(yc, "info");

        print_unit(
            'n',
            ctx->node_dgen,
            m->compc,
            m->comp_rule,
            0,
            m->num_keys,
            m->num_tombstones,
            m->nptombs,
            m->header_bytes,
            m->tot_key_bytes,
            m->tot_val_bytes,
            ctx->kvset_idx,
            ctx->node_hblks,
            ctx->node_kblks,
            ctx->node_vblks,
            yc);

        yaml_end_element(yc);
        yaml_end_element_type(yc);

        ctx->prev_elem = TYPE_NODE;

        /* Each node resets the kvset_idx */
        ctx->kvset_idx = 0;
        break;

    default:
        ev_warn(1);
        break;
    }
}

static int
print_tree(struct ctx *ctx, struct cn_node_loc *loc, struct kvset *kvset)
{
    struct kvset_metrics km;

    /* A null kvset is the start of a new node */
    if (!kvset) {
        if (ctx->tot_nodes > 0)
            print_elem("node", ctx, &ctx->node, &ctx->node_loc, 0);
        memset(&ctx->node, 0, sizeof(ctx->node));
        ctx->node_loc = *loc;
        ctx->node_hblks = 0;
        ctx->node_kblks = 0;
        ctx->node_vblks = 0;
        ctx->node_dgen = 0;
        ++ctx->tot_nodes;
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

    ctx->total.num_keys += km.num_keys;
    ctx->total.num_tombstones += km.num_tombstones;
    ctx->total.nptombs += km.nptombs;
    ctx->total.num_kblocks += km.num_kblocks;
    ctx->total.num_vblocks += km.num_vblocks;
    ctx->total.header_bytes += km.header_bytes;
    ctx->total.tot_key_bytes += km.tot_key_bytes;
    ctx->total.tot_val_bytes += km.tot_val_bytes;

    print_elem("kvset", ctx, &km, loc, kvset);

    return 0;
}

merr_t
kvs_rest_query_tree(struct kvdb_kvs *kvs, struct yaml_context *yc, bool list)
{
    struct cn *           cn = kvs_cn(kvs->kk_ikvs);
    struct ctx            ctx;
    struct table *        tree_view;
    struct kvset_metrics *m;
    int                   i;
    merr_t                err;

    if (ev(!cn))
        return merr(EINVAL);

    memset(&ctx, 0, sizeof(ctx));
    ctx.yc = yc;
    ctx.prev_elem = TYPE_BEGIN;
    ctx.list = list;

    yaml_start_element_type(yc, "nodes");

    err = cn_tree_view_create(cn, &tree_view);
    if (ev(err))
        return err;

    for (i = 0; i < table_len(tree_view); i++) {
        int                rc;
        struct kvset_view *v = table_at(tree_view, i);

        rc = print_tree(&ctx, &v->node_loc, v->kvset);
        if (rc)
            break;
    }

    cn_tree_view_destroy(tree_view);

    print_elem("node", &ctx, &ctx.node, &ctx.node_loc, 0);

    yaml_end_element_type(yc); /* nodes */

    yaml_start_element_type(yc, "info");

    m = &ctx.total;

    print_unit(
        't',
        ctx.tree_dgen,
        m->compc,
        m->comp_rule,
        0,
        m->num_keys,
        m->num_tombstones,
        m->nptombs,
        m->header_bytes,
        m->tot_key_bytes,
        m->tot_val_bytes,
        ctx.tot_kvsets,
        ctx.tot_hblks,
        ctx.tot_kblks,
        ctx.tot_vblks,
        yc);

    yaml_field_fmt(yc, "nodes", "%u", ctx.tot_nodes);
    yaml_field_fmt(yc, "cnid", "%lu", kvs->kk_cnid);
    yaml_field_fmt(yc, "name", kvs->kk_name);
    yaml_field_fmt(yc, "open", "yes");

    yaml_end_element(yc);

    yaml_end_element(yc);
    yaml_end_element_type(yc); /* info */

    return 0;
}

static merr_t
rest_kvs_tree(
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
    struct kvdb_kvs *kvs = context;
    struct rest_kv *kv = NULL;
    bool list_blkid = true;

    /* verify that the request was exact */
    if (ev(strcmp(path, url) != 0))
        return merr(E2BIG);

    /* HSE_REVISIT: It is not safe to make a ref out of thin air.
     * The ref should be obtained when this endpoint is registered.
     */
    atomic_inc(&kvs->kk_refcnt);

    if (!kvs->kk_ikvs) {
        /* kvs is closed */
        yaml_start_element_type(&yc, "info");
        yaml_field_fmt(&yc, "cnid", "%lu", kvs->kk_cnid);
        yaml_field_fmt(&yc, "name", kvs->kk_name);
        yaml_field_fmt(&yc, "open", "no");
        yaml_end_element(&yc);
        yaml_end_element_type(&yc); /* info */
        yc.yaml_emit(&yc);

        atomic_dec(&kvs->kk_refcnt);
        return 0;
    }

    switch (rest_kv_count(iter)) {
    case 0:
        list_blkid = false;
        break;

    case 1:
        kv = rest_kv_next(iter);
        if (strcmp(kv->key, "list_blkid") == 0) {
            if (strcmp(kv->value, "false") == 0) {
                list_blkid = false;
            } else if (strcmp(kv->value, "true") == 0) {
                list_blkid = true;
            } else {
                atomic_dec(&kvs->kk_refcnt);
                return merr(EINVAL);
            }
        } else {
            atomic_dec(&kvs->kk_refcnt);
            return merr(EINVAL);
        }
        break;

    default:
        atomic_dec(&kvs->kk_refcnt);
        return merr(E2BIG);
    }

    kvs_rest_query_tree(kvs, &yc, list_blkid);
    yc.yaml_emit(&yc);

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
