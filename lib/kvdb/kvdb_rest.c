/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/flags.h>

#include <hse_util/slab.h>
#include <hse_util/logging.h>
#include <hse_util/hse_err.h>
#include <hse_util/parse_num.h>
#include <hse_util/event_counter.h>
#include <hse_util/fmt.h>

#include <hse_util/data_tree.h>
#include <hse_util/rest_api.h>
#include <hse_util/spinlock.h>
#include <hse_util/string.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/cn_tree_view.h>

#include "kvdb_rest.h"
#include "kvdb_kvs.h"

/* yaml2fd():
 * Write each line to fd instead of building up yaml formatted data in a
 * buffer. yaml_buf needs to be large enough for one line of yaml
 *   - Only maintain yaml_indent across multiple calls.
 *   - Set yaml_offset to zero at the beginning of each call.
 *   - Scrub yaml_buf
 */

#define _yaml2fd(rc, outfd, yaml_func, yc, ...)                            \
    do {                                                                   \
        (yc)->yaml_offset = 0;                                             \
        (yaml_func)((yc), ##__VA_ARGS__);                                  \
        (*rc) = rest_write_safe(outfd, (yc)->yaml_buf, (yc)->yaml_offset); \
        memset((yc)->yaml_buf, 0, (yc)->yaml_buf_sz);                      \
    } while (0)

#define yaml2fd(outfd, yaml_func, yc, ...)                 \
    ({                                                     \
        ssize_t r;                                         \
        _yaml2fd(&r, outfd, yaml_func, yc, ##__VA_ARGS__); \
        (r);                                               \
    })

/*---------------------------------------------------------------
 * rest: get handler for kvdb
 */
static merr_t
get_kvs_list(struct ikvdb *ikvdb, int fd, struct yaml_context *yc)
{
    char ** kvs_list;
    size_t  kvs_cnt;
    int     i;
    merr_t  err;

    err = ikvdb_kvs_names_get(ikvdb, &kvs_cnt, &kvs_list);
    if (ev(err))
        return err;

    yaml2fd(fd, yaml_start_element_type, yc, "kvs_list");
    for (i = 0; i < kvs_cnt; i++)
        yaml2fd(fd, yaml_list_fmt, yc, kvs_list[i]);
    yaml2fd(fd, yaml_end_element_type, yc);

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
    struct ikvdb *      ikvdb = context;
    merr_t              err;
    struct yaml_context yc = { 0 };

    /* verify that the request was exact */
    if (strcmp(path, url) != 0)
        return merr(ev(E2BIG));

    yc.yaml_indent = 0;
    yc.yaml_offset = 0;
    yc.yaml_buf = info->buf;
    yc.yaml_buf_sz = info->buf_sz;
    yc.yaml_emit = NULL;

    err = get_kvs_list(ikvdb, info->resp_fd, &yc);
    if (ev(err))
        return err;

    return 0;
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
    if (strcmp(action, "request") == 0)
        ikvdb_compact(ikvdb, flags);
    else
        return merr(ev(EINVAL));

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

static merr_t
rest_kvdb_storage_stats_get(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    struct ikvdb *               ikvdb = context;
    struct hse_kvdb_storage_info stinfo = {};
    size_t                       b, bufoff;
    char *                       buf = info->buf;
    size_t                       bufsz = info->buf_sz;
    merr_t                       err;

    err = ikvdb_storage_info_get(ikvdb, &stinfo);
    if (err)
        return err;

    bufoff = 0;
    b = snprintf_append(buf, bufsz, &bufoff, "total: %lu\n", stinfo.total_bytes);
    b += snprintf_append(buf, bufsz, &bufoff, "available: %lu\n", stinfo.available_bytes);
    b += snprintf_append(buf, bufsz, &bufoff, "allocated: %lu\n", stinfo.allocated_bytes);
    b += snprintf_append(buf, bufsz, &bufoff, "used: %lu\n", stinfo.used_bytes);

    if (write(info->resp_fd, buf, b) != b)
        return merr(EIO);

    return 0;
}

merr_t
kvdb_rest_register(struct ikvdb *kvdb)
{
    merr_t status, err = 0;

    if (!kvdb)
        return merr(ev(EINVAL));

    status =
        rest_url_register(kvdb, URL_FLAG_EXACT, rest_kvdb_get, 0, "kvdb/%s", ikvdb_alias(kvdb));
    if (ev(status) && !err)
        err = status;

    status = rest_url_register(
        kvdb,
        URL_FLAG_EXACT,
        rest_kvdb_storage_stats_get,
        NULL,
        "kvdb/%s/storage_stats",
        ikvdb_alias(kvdb));
    if (ev(status) && !err)
        err = status;

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
    int                  fd;
    bool                 list; /* whether or not to print block ids */

    struct kvset_metrics total;
    struct kvset_metrics node;

    enum elem_type prev_elem;

    /* per node */
    struct cn_node_loc node_loc; /* cached loc */
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
    u32 tot_kblks;
    u32 tot_vblks;
    u32 max_depth;
    u64 tree_dgen;
};

enum mb_type { TYPE_KBLK, TYPE_VBLK };

static void
print_ids(struct kvset *kvset, enum mb_type type, int fd, struct yaml_context *yc)
{
    int i, n = 0;

    switch (type) {
        case TYPE_KBLK:
            n = kvset_get_num_kblocks(kvset);
            for (i = 0; i < n; ++i)
                yaml2fd(fd, yaml_list_fmt, yc, "0x%lx", kvset_get_nth_kblock_id(kvset, i));
            break;
        case TYPE_VBLK:
            n = kvset_get_num_vblocks(kvset);
            for (i = 0; i < n; ++i)
                yaml2fd(fd, yaml_list_fmt, yc, "0x%lx", kvset_get_nth_vblock_id(kvset, i));
            break;
    }

    if (n > 0)
        yaml2fd(fd, yaml_end_element, yc);
}

static void
print_unit(
    int                  type,
    u64                  dgen,
    u16                  compc,
    u32                  vgroups,
    u64                  nkeys,
    u64                  ntombs,
    u64                  klen,
    u64                  vlen,
    int                  nkvsets,
    int                  nkblks,
    int                  nvblks,
    int                  fd,
    struct yaml_context *yc)
{
    yaml2fd(fd, yaml_field_fmt, yc, "dgen", "%lu", dgen);
    yaml2fd(fd, yaml_field_fmt, yc, "nkeys", "%lu", nkeys);
    yaml2fd(fd, yaml_field_fmt, yc, "ntombs", "%lu", ntombs);
    if (type == 'k') {
        yaml2fd(fd, yaml_field_fmt, yc, "compc", "%u", compc);
        yaml2fd(fd, yaml_field_fmt, yc, "vgroups", "%u", vgroups);
    }
    yaml2fd(fd, yaml_field_fmt, yc, "klen", "%lu", klen);
    yaml2fd(fd, yaml_field_fmt, yc, "vlen", "%lu", vlen);

    if (nkvsets >= 0) /* do not print these fields for kvsets */
        yaml2fd(fd, yaml_field_fmt, yc, "nkvsets", "%d", nkvsets);

    yaml2fd(fd, yaml_field_fmt, yc, "nkblks", "%d", nkblks);
    yaml2fd(fd, yaml_field_fmt, yc, "nvblks", "%d", nvblks);
}

static void
print_elem(
    const char *          who,
    struct ctx *          ctx,
    struct kvset_metrics *m,
    struct cn_node_loc *  loc,
    struct kvset *        kvset)
{
    char                 idx[10];
    struct yaml_context *yc = ctx->yc;
    int                  fd = ctx->fd;

    if (ctx->prev_elem == TYPE_NODE) {
        /* This is the start of a new node */
        yaml2fd(fd, yaml_start_element, yc, "loc", "");
        yc->yaml_indent++;
        yaml2fd(fd, yaml_field_fmt, yc, "level", "%u", loc->node_level);
        yaml2fd(fd, yaml_field_fmt, yc, "offset", "%u", loc->node_offset);
        yc->yaml_indent--;
    }

    switch (who[0]) {
        case 'k':
            snprintf(idx, sizeof(idx), "%u", ctx->kvset_idx++);

            if (ctx->prev_elem == TYPE_NODE)
                yaml2fd(ctx->fd, yaml_start_element_type, yc, "kvsets");

            yaml2fd(ctx->fd, yaml_start_element, yc, "index", idx);

            print_unit(
                'k',
                ctx->kvset_dgen,
                m->compc,
                m->vgroups,
                m->num_keys,
                m->num_tombstones,
                m->tot_key_bytes,
                m->tot_val_bytes,
                -1,
                ctx->num_kblks,
                ctx->num_vblks,
                ctx->fd,
                yc);

            if (ctx->list) {
                yaml2fd(ctx->fd, yaml_start_element_type, yc, "kblks");
                print_ids(kvset, TYPE_KBLK, ctx->fd, yc);
                yaml2fd(ctx->fd, yaml_end_element_type, yc);

                yaml2fd(ctx->fd, yaml_start_element_type, yc, "vblks");
                print_ids(kvset, TYPE_VBLK, ctx->fd, yc);
                yaml2fd(ctx->fd, yaml_end_element_type, yc);
            }

            yaml2fd(ctx->fd, yaml_end_element, yc); /* index */

            ctx->prev_elem = TYPE_KVSET;
            break;

        case 'n':
            if (ctx->prev_elem == TYPE_KVSET)
                yaml2fd(ctx->fd, yaml_end_element_type, yc); /* kvsets */

            yaml2fd(ctx->fd, yaml_start_element_type, yc, "info");
            print_unit(
                'n',
                ctx->node_dgen,
                m->compc,
                0,
                m->num_keys,
                m->num_tombstones,
                m->tot_key_bytes,
                m->tot_val_bytes,
                ctx->kvset_idx,
                ctx->node_kblks,
                ctx->node_vblks,
                ctx->fd,
                yc);
            yaml2fd(ctx->fd, yaml_end_element, yc);
            yaml2fd(ctx->fd, yaml_end_element_type, yc);

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
        ctx->node_kblks = 0;
        ctx->node_vblks = 0;
        ctx->node_dgen = 0;
        ++ctx->tot_nodes;
        return 0;
    }

    kvset_get_metrics(kvset, &km);

    ++ctx->tot_kvsets;
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

    if (loc->node_level > ctx->max_depth)
        ctx->max_depth = loc->node_level;

    ctx->node.num_keys += km.num_keys;
    ctx->node.num_tombstones += km.num_tombstones;
    ctx->node.num_kblocks += km.num_kblocks;
    ctx->node.num_vblocks += km.num_vblocks;
    ctx->node.tot_key_bytes += km.tot_key_bytes;
    ctx->node.tot_val_bytes += km.tot_val_bytes;

    ctx->total.num_keys += km.num_keys;
    ctx->total.num_tombstones += km.num_tombstones;
    ctx->total.num_kblocks += km.num_kblocks;
    ctx->total.num_vblocks += km.num_vblocks;
    ctx->total.tot_key_bytes += km.tot_key_bytes;
    ctx->total.tot_val_bytes += km.tot_val_bytes;

    print_elem("kvset", ctx, &km, loc, kvset);

    return 0;
}

merr_t
kvs_rest_query_tree(struct kvdb_kvs *kvs, struct yaml_context *yc, int fd, bool list)
{
    struct cn *           cn = kvs_cn(kvs->kk_ikvs);
    struct ctx            ctx;
    struct table *        tree_view;
    struct kvset_metrics *m;
    int                   i;
    merr_t                err;

    if (!cn)
        return merr(ev(EINVAL));

    memset(&ctx, 0, sizeof(ctx));
    ctx.yc = yc;
    ctx.fd = fd;
    ctx.prev_elem = TYPE_BEGIN;
    ctx.list = list;

    yaml2fd(ctx.fd, yaml_start_element_type, yc, "nodes");

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

    yaml2fd(ctx.fd, yaml_end_element_type, yc); /* nodes */

    yaml2fd(ctx.fd, yaml_start_element_type, yc, "info");

    m = &ctx.total;

    yaml2fd(ctx.fd, yaml_field_fmt, yc, "name", kvs->kk_name);
    yaml2fd(ctx.fd, yaml_field_fmt, yc, "cnid", "%lu", kvs->kk_cnid);
    yaml2fd(ctx.fd, yaml_field_fmt, yc, "open", "yes");
    print_unit(
        't',
        ctx.tree_dgen,
        m->compc,
        0,
        m->num_keys,
        m->num_tombstones,
        m->tot_key_bytes,
        m->tot_val_bytes,
        ctx.tot_kvsets,
        ctx.tot_kblks,
        ctx.tot_vblks,
        ctx.fd,
        yc);

    yaml2fd(
        ctx.fd,
        yaml_field_fmt,
        yc,
        "max_depth",
        "%u",
        ctx.tot_nodes > 0 ? ctx.max_depth + 1 : ctx.max_depth);

    yaml2fd(ctx.fd, yaml_field_fmt, yc, "nodes", "%u", ctx.tot_nodes);

    yaml2fd(ctx.fd, yaml_end_element, yc);

    yaml2fd(ctx.fd, yaml_end_element, yc);
    yaml2fd(ctx.fd, yaml_end_element_type, yc); /* info */

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
    struct kvdb_kvs *   kvs = context;
    struct rest_kv *    kv = 0;
    bool                list_blkid = true;
    struct yaml_context yc = { 0 };
    int                 fd = info->resp_fd;

    /* verify that the request was exact */
    if (strcmp(path, url) != 0)
        return merr(ev(E2BIG));

    yc.yaml_indent = 0;
    yc.yaml_offset = 0;
    yc.yaml_buf = info->buf;
    yc.yaml_buf_sz = info->buf_sz;
    yc.yaml_emit = NULL;

    /* HSE_REVISIT: It is not safe to make a ref out of thin air.
     * The ref should be obtained when this endpoint is registered.
     */
    atomic_inc(&kvs->kk_refcnt);

    if (!kvs->kk_ikvs) {
        /* kvs is closed */
        yaml2fd(fd, yaml_start_element_type, &yc, "info");
        yaml2fd(fd, yaml_field_fmt, &yc, "name", kvs->kk_name);
        yaml2fd(fd, yaml_field_fmt, &yc, "cnid", "%lu", kvs->kk_cnid);
        yaml2fd(fd, yaml_field_fmt, &yc, "open", "no");
        yaml2fd(fd, yaml_end_element, &yc);
        yaml2fd(fd, yaml_end_element_type, &yc); /* info */

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
                    return merr(ev(EINVAL));
                }
            } else {
                atomic_dec(&kvs->kk_refcnt);
                return merr(ev(EINVAL));
            }
            break;
        default:
            atomic_dec(&kvs->kk_refcnt);
            return merr(ev(E2BIG));
    }

    kvs_rest_query_tree(kvs, &yc, fd, list_blkid);

    atomic_dec(&kvs->kk_refcnt);

    return 0;
}

merr_t
kvs_rest_register(struct ikvdb *const kvdb, const char *kvs_name, void *kvs)
{
    merr_t err = 0;
    merr_t status;

    if (!kvs_name || !kvs)
        return merr(ev(EINVAL));

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

    if (!kvs_name)
        return merr(ev(EINVAL));

    status = rest_url_deregister("kvdb/%s/kvs/%s/cn/tree", ikvdb_alias(kvdb), kvs_name);

    if (ev(status) && !err)
        err = status;

    return err;
}
