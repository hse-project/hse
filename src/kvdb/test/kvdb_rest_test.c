/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/string.h>
#include <hse_util/rest_api.h>
#include <hse_util/rest_client.h>

#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/cn_node_loc.h>
#include <hse_ikvdb/cn_tree_view.h>
#include <hse_ikvdb/ikvdb.h>

#define MP "kvdb_rest_mp"
#define SOCK "/tmp/" MP ".rest"

#define KVS "kvdb_rest_kvs"
#define KVS1 KVS "1"
#define KVS2 KVS "2"
#define KVS3 KVS "3"

#include "mock_c0cn.h"
#include "mock_c1.h"
#include "../kvdb_rest.h"
#include "../../cn/kvset.h"
#include "../../cn/cn_metrics.h"

struct hse_params *params;
struct ikvdb *     store;
char               sock[PATH_MAX];

static int
set_sock(struct mtf_test_info *ti)
{
    snprintf(sock, sizeof(sock), "%s.%d", SOCK, getpid());
    return 0;
}

bool ct_view_two_level = false;
bool ct_view_two_kvsets = false;
bool ct_view_do_nothing = false;
merr_t
_cn_tree_view_create(struct cn *cn, struct table **view_out)
{
    struct table *     view;
    struct kvset_view *v;

    if (ct_view_do_nothing) {
        *view_out = 0;
        return 0;
    }

    view = table_create(5, sizeof(struct kvset_view), true);

    /* root node */
    v = table_append(view);

    v->kvset = 0;
    v->node_loc.node_level = 0;
    v->node_loc.node_offset = 0;

    if (ct_view_two_level) {
        /* another node */
        v = table_append(view);
        v->kvset = 0;
        v->node_loc.node_level = 1;
        v->node_loc.node_offset = 0;
    }

    /* kvset */
    v = table_append(view);
    v->kvset = (struct kvset *)-1;
    v->node_loc.node_level = ct_view_two_level ? 1 : 0;
    v->node_loc.node_offset = 0;

    /* another kvset */
    if (ct_view_two_kvsets) {
        v = table_append(view);
        v->kvset = (struct kvset *)-1;
        v->node_loc.node_level = ct_view_two_level ? 1 : 0;
        v->node_loc.node_offset = 0;
    }

    *view_out = view;

    return 0;
}

void
_cn_tree_view_destroy(struct table *view)
{
    if (ct_view_do_nothing)
        return;

    table_destroy(view);
}

void
_kvset_get_metrics(struct kvset *kvset, struct kvset_metrics *metrics)
{
    if (!metrics)
        return;

    metrics->num_keys = 1000000;
    metrics->num_tombstones = 0;
    metrics->num_kblocks = 1;
    metrics->num_vblocks = 1;
    metrics->tot_key_bytes = 4000000;
    metrics->tot_val_bytes = 8000000;
    metrics->compc = 0;
    metrics->vgroups = 1;
}

struct kvs_cparams cp;

static int
test_pre(struct mtf_test_info *ti)
{
    merr_t          err;
    struct mpool *  ds = (struct mpool *)-1;
    struct hse_kvs *kvs1 = 0;
    struct hse_kvs *kvs2 = 0;

    /* Mocks */
    mapi_inject_clear();

    mapi_inject(mapi_idx_mpool_mdc_get_root, 0);
    mapi_inject(mapi_idx_mpool_mdc_open, 0);
    mapi_inject(mapi_idx_mpool_mdc_close, 0);
    mapi_inject(mapi_idx_mpool_mdc_append, 0);
    mapi_inject(mapi_idx_mpool_mdc_cstart, 0);
    mapi_inject(mapi_idx_mpool_mdc_cend, 0);
    mapi_inject(mapi_idx_mpool_mdc_usage, 0);
    mapi_inject(mapi_idx_mpool_mdc_rewind, 0);
    mapi_inject(mapi_idx_mpool_mdc_read, 0);
    mapi_inject(mapi_idx_mpool_mclass_get, ENOENT);
    mapi_inject(mapi_idx_kvdb_log_replay, 0);
    mapi_inject(mapi_idx_kvdb_log_done, 0);

    mapi_inject_ptr(mapi_idx_cndb_cn_cparams, &cp);

    mapi_inject(mapi_idx_cn_get_tree, 0);

    mapi_inject(mapi_idx_cndb_replay, 0);
    mapi_inject(mapi_idx_cndb_cn_make, 0);

    mapi_inject(mapi_idx_kvset_get_num_kblocks, 1);
    mapi_inject(mapi_idx_kvset_get_nth_kblock_id, 0x70310d);
    mapi_inject(mapi_idx_kvset_get_num_vblocks, 1);
    mapi_inject(mapi_idx_kvset_get_nth_vblock_id, 0x70310e);

    mock_c0cn_set();
    mock_c1_set();

    mapi_inject(mapi_idx_c0_get_pfx_len, 0);

    MOCK_SET(ct_view, _cn_tree_view_create);
    MOCK_SET(ct_view, _cn_tree_view_destroy);
    ct_view_do_nothing = true;

    MOCK_SET(kvset_view, _kvset_get_metrics);

    /* Rest */
    rest_init();

    rest_server_start(sock);

    hse_params_create(&params);

    err = hse_params_set(params, "kvdb.dur_enable", "0");
    assert(err == 0);

    err = ikvdb_open(MP, ds, params, &store);
    err = ikvdb_kvs_make(store, KVS1, 0);
    err = ikvdb_kvs_make(store, KVS2, 0);
    err = ikvdb_kvs_make(store, KVS3, 0);

    err = ikvdb_kvs_open(store, KVS1, 0, 0, &kvs1);
    assert(err == 0);

    err = ikvdb_kvs_open(store, KVS2, 0, 0, &kvs2);
    assert(err == 0);

    return 0;
}

static int
test_post(struct mtf_test_info *ti)
{
    MOCK_UNSET(kvset_view, _kvset_get_metrics);

    rest_server_stop();

    rest_destroy();

    ikvdb_close(store);
    store = 0;

    hse_params_destroy(params);

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(kvdb_rest, set_sock);

MTF_DEFINE_UTEST_PREPOST(kvdb_rest, kvs_list_test, test_pre, test_post)
{
    char path[64];
    char buf[4096] = { 0 };
    char exp[4096] = { 0 };

    struct yaml_context yc = {
        .yaml_indent = 0,
        .yaml_offset = 0,
        .yaml_buf = exp,
        .yaml_buf_sz = sizeof(exp),
        .yaml_emit = NULL,
    };
    merr_t err;

    snprintf(path, sizeof(path), "mpool/%s", MP);

    yaml_start_element_type(&yc, "kvs_list");
    yaml_element_list(&yc, KVS1);
    yaml_element_list(&yc, KVS2);
    yaml_element_list(&yc, KVS3);
    yaml_end_element_type(&yc);

    err = curl_get(path, sock, buf, sizeof(buf));
    ASSERT_EQ(0, err);
    ASSERT_STREQ(exp, buf);
}

MTF_DEFINE_UTEST_PREPOST(kvdb_rest, cn_metrics, test_pre, test_post)
{
    char   path[128];
    char   buf[4096];
    char   unopened[4096] = { 0 };
    merr_t err;

    struct yaml_context yc = {
        .yaml_indent = 0,
        .yaml_offset = 0,
        .yaml_buf = unopened,
        .yaml_buf_sz = sizeof(unopened),
        .yaml_emit = NULL,
    };

    yaml_start_element_type(&yc, "info");
    yaml_element_field(&yc, "name", KVS3);
    /* cnids are minted by cNDDB, but cNDB is mocked, so cnid will be 0 */
    yaml_element_field(&yc, "cnid", "0");
    yaml_element_field(&yc, "open", "no");
    yaml_end_element(&yc);
    yaml_end_element_type(&yc); /* info */

    /* kvs in open state */
    snprintf(path, sizeof(path), "mpool/%s/kvs/%s/cn/tree", MP, KVS1);
    memset(buf, 0, sizeof(buf));
    err = curl_get(path, sock, buf, sizeof(buf));
    ASSERT_EQ(0, err);

    /* unopened kvs */
    snprintf(path, sizeof(path), "mpool/%s/kvs/%s/cn/tree", MP, KVS3);
    memset(buf, 0, sizeof(buf));
    err = curl_get(path, sock, buf, sizeof(buf));
    ASSERT_EQ(0, err);
    ASSERT_STREQ(unopened, buf);

    /* invalid arg */
    snprintf(path, sizeof(path), "mpool/%s/kvs/%s/cn/tree?arg", MP, KVS1);
    memset(buf, 0, sizeof(buf));
    err = curl_get(path, sock, buf, sizeof(buf));
    ASSERT_EQ(0, buf[0]);
    ASSERT_EQ(0, err);

    snprintf(path, sizeof(path), "mpool/%s/kvs/%s/cn/tree?arg=val", MP, KVS1);
    memset(buf, 0, sizeof(buf));
    err = curl_get(path, sock, buf, sizeof(buf));
    ASSERT_EQ(0, buf[0]);
    ASSERT_EQ(0, err);

    /* too many args */
    snprintf(path, sizeof(path), "mpool/%s/kvs/%s/cn/tree?kblist&arg1=val1&arg2=val2", MP, KVS1);
    memset(buf, 0, sizeof(buf));
    err = curl_get(path, sock, buf, sizeof(buf));
    ASSERT_EQ(0, buf[0]);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(kvdb_rest, cn_tree_view_create_failure, test_pre, test_post)
{
    char   path[128];
    char   buf[4096] = { 0 };
    merr_t err;

    mapi_inject(mapi_idx_cn_tree_view_create, merr(EBUG));
    snprintf(path, sizeof(path), "mpool/%s/kvs/%s/cn/tree", MP, KVS1);

    err = curl_get(path, sock, buf, sizeof(buf));

    /* since the error wasn't a communication error, nor was it a failure
     * before the server started responding, the http_code is already set to
     * HTTP_OK.
     * So, curl doesn't see an error.
     */
    ASSERT_EQ(0, err);
    mapi_inject_unset(mapi_idx_cn_tree_view_create);
}

MTF_DEFINE_UTEST_PREPOST(kvdb_rest, unexact_paths, test_pre, test_post)
{
    char   path[128];
    char   buf[1024];
    merr_t err;

    snprintf(path, sizeof(path), "mpool/%s/kvs/%s", MP, KVS1);

    memset(buf, 0, sizeof(buf));
    err = curl_get(path, sock, buf, sizeof(buf));
    ASSERT_EQ(0, buf[0]);
    ASSERT_EQ(0, err);

    snprintf(path, sizeof(path), "mpool/%s/kkk", MP);
    memset(buf, 0, sizeof(buf));
    err = curl_get(path, sock, buf, sizeof(buf));
    ASSERT_EQ(0, buf[0]);
    ASSERT_EQ(0, err);
}

/* Tests to verify yaml output of the cn_tree
 */
MTF_DEFINE_UTEST_PREPOST(kvdb_rest, print_tree_test, test_pre, test_post)
{
    char        path[128];
    char        buf[4096] = { 0 };
    const char *exp = "nodes:\n"
                      "- loc: \n"
                      "    level: 0\n"
                      "    offset: 0\n"
                      "  kvsets:\n"
                      "  - index: 0\n"
                      "    dgen: 1\n"
                      "    nkeys: 1000000\n"
                      "    ntombs: 0\n"
                      "    compc: 0\n"
                      "    vgroups: 1\n"
                      "    klen: 4000000\n"
                      "    vlen: 8000000\n"
                      "    nkblks: 1\n"
                      "    nvblks: 1\n"
                      "    kblks:\n"
                      "      - 0x70310d\n"
                      "    vblks:\n"
                      "      - 0x70310e\n"
                      "  info:\n"
                      "    dgen: 1\n"
                      "    nkeys: 1000000\n"
                      "    ntombs: 0\n"
                      "    klen: 4000000\n"
                      "    vlen: 8000000\n"
                      "    nkvsets: 1\n"
                      "    nkblks: 1\n"
                      "    nvblks: 1\n"
                      "info:\n"
                      "  name: kvdb_rest_kvs1\n"
                      "  cnid: 0\n"
                      "  open: yes\n"
                      "  dgen: 1\n"
                      "  nkeys: 1000000\n"
                      "  ntombs: 0\n"
                      "  klen: 4000000\n"
                      "  vlen: 8000000\n"
                      "  nkvsets: 1\n"
                      "  nkblks: 1\n"
                      "  nvblks: 1\n"
                      "  max_depth: 1\n"
                      "  nodes: 1\n";

    merr_t err;

    mapi_inject_once(mapi_idx_kvset_get_dgen, 1, 1);

    MOCK_SET(ct_view, _cn_tree_view_create);
    MOCK_SET(ct_view, _cn_tree_view_destroy);

    ct_view_do_nothing = false;

    snprintf(path, sizeof(path), "mpool/%s/kvs/%s/cn/tree?list_blkid=true", MP, KVS1);

    err = curl_get(path, sock, buf, sizeof(buf));
    ASSERT_EQ(0, err);
    ASSERT_STREQ(exp, buf);

    ct_view_do_nothing = true;
    MOCK_UNSET(ct_view, _cn_tree_view_create);
    MOCK_UNSET(ct_view, _cn_tree_view_destroy);
}

MTF_DEFINE_UTEST_PREPOST(kvdb_rest, empty_root_test, test_pre, test_post)
{
    char        path[128];
    char        buf[4096] = { 0 };
    const char *exp = "nodes:\n"
                      "- loc: \n"
                      "    level: 0\n"
                      "    offset: 0\n"
                      "  info:\n"
                      "    dgen: 0\n"
                      "    nkeys: 0\n"
                      "    ntombs: 0\n"
                      "    klen: 0\n"
                      "    vlen: 0\n"
                      "    nkvsets: 0\n"
                      "    nkblks: 0\n"
                      "    nvblks: 0\n"
                      "- loc: \n"
                      "    level: 1\n"
                      "    offset: 0\n"
                      "  kvsets:\n"
                      "  - index: 0\n"
                      "    dgen: 1\n"
                      "    nkeys: 1000000\n"
                      "    ntombs: 0\n"
                      "    compc: 0\n"
                      "    vgroups: 1\n"
                      "    klen: 4000000\n"
                      "    vlen: 8000000\n"
                      "    nkblks: 1\n"
                      "    nvblks: 1\n"
                      "    kblks:\n"
                      "      - 0x70310d\n"
                      "    vblks:\n"
                      "      - 0x70310e\n"
                      "  info:\n"
                      "    dgen: 1\n"
                      "    nkeys: 1000000\n"
                      "    ntombs: 0\n"
                      "    klen: 4000000\n"
                      "    vlen: 8000000\n"
                      "    nkvsets: 1\n"
                      "    nkblks: 1\n"
                      "    nvblks: 1\n"
                      "info:\n"
                      "  name: kvdb_rest_kvs2\n"
                      "  cnid: 0\n"
                      "  open: yes\n"
                      "  dgen: 1\n"
                      "  nkeys: 1000000\n"
                      "  ntombs: 0\n"
                      "  klen: 4000000\n"
                      "  vlen: 8000000\n"
                      "  nkvsets: 1\n"
                      "  nkblks: 1\n"
                      "  nvblks: 1\n"
                      "  max_depth: 2\n"
                      "  nodes: 2\n";

    merr_t err;

    mapi_inject_once(mapi_idx_kvset_get_dgen, 1, 1);

    MOCK_SET(ct_view, _cn_tree_view_create);
    MOCK_SET(ct_view, _cn_tree_view_destroy);

    ct_view_two_level = true;
    ct_view_do_nothing = false;

    snprintf(path, sizeof(path), "mpool/%s/kvs/%s/cn/tree?list_blkid=true", MP, KVS2);

    err = curl_get(path, sock, buf, sizeof(buf));
    ASSERT_EQ(0, err);
    ASSERT_STREQ(exp, buf);

    ct_view_two_level = false;
    ct_view_do_nothing = true;

    MOCK_UNSET(ct_view, _cn_tree_view_create);
    MOCK_UNSET(ct_view, _cn_tree_view_destroy);
}

static int count;
u64
_kvset_get_dgen(struct kvset *km)
{
    count++;
    return 4 * (count);
}

MTF_DEFINE_UTEST_PREPOST(kvdb_rest, list_without_blkids, test_pre, test_post)
{
    char        path[128];
    char        buf[4096] = { 0 };
    const char *exp = "nodes:\n"
                      "- loc: \n"
                      "    level: 0\n"
                      "    offset: 0\n"
                      "  info:\n"
                      "    dgen: 0\n"
                      "    nkeys: 0\n"
                      "    ntombs: 0\n"
                      "    klen: 0\n"
                      "    vlen: 0\n"
                      "    nkvsets: 0\n"
                      "    nkblks: 0\n"
                      "    nvblks: 0\n"
                      "- loc: \n"
                      "    level: 1\n"
                      "    offset: 0\n"
                      "  kvsets:\n"
                      "  - index: 0\n"
                      "    dgen: 4\n"
                      "    nkeys: 1000000\n"
                      "    ntombs: 0\n"
                      "    compc: 0\n"
                      "    vgroups: 1\n"
                      "    klen: 4000000\n"
                      "    vlen: 8000000\n"
                      "    nkblks: 1\n"
                      "    nvblks: 1\n"
                      "  - index: 1\n"
                      "    dgen: 8\n"
                      "    nkeys: 1000000\n"
                      "    ntombs: 0\n"
                      "    compc: 0\n"
                      "    vgroups: 1\n"
                      "    klen: 4000000\n"
                      "    vlen: 8000000\n"
                      "    nkblks: 1\n"
                      "    nvblks: 1\n"
                      "  info:\n"
                      "    dgen: 8\n"
                      "    nkeys: 2000000\n"
                      "    ntombs: 0\n"
                      "    klen: 8000000\n"
                      "    vlen: 16000000\n"
                      "    nkvsets: 2\n"
                      "    nkblks: 2\n"
                      "    nvblks: 2\n"
                      "info:\n"
                      "  name: kvdb_rest_kvs2\n"
                      "  cnid: 0\n"
                      "  open: yes\n"
                      "  dgen: 8\n"
                      "  nkeys: 2000000\n"
                      "  ntombs: 0\n"
                      "  klen: 8000000\n"
                      "  vlen: 16000000\n"
                      "  nkvsets: 2\n"
                      "  nkblks: 2\n"
                      "  nvblks: 2\n"
                      "  max_depth: 2\n"
                      "  nodes: 2\n";

    merr_t err;

    MOCK_SET(ct_view, _cn_tree_view_create);
    MOCK_SET(ct_view, _cn_tree_view_destroy);

    ct_view_two_level = true;
    ct_view_two_kvsets = true;
    ct_view_do_nothing = false;

    MOCK_SET(kvset_view, _kvset_get_dgen);

    snprintf(path, sizeof(path), "mpool/%s/kvs/%s/cn/tree?list_blkid=false", MP, KVS2);

    err = curl_get(path, sock, buf, sizeof(buf));
    ASSERT_EQ(0, err);
    ASSERT_STREQ(exp, buf);

    count = 0;
    snprintf(path, sizeof(path), "mpool/%s/kvs/%s/cn/tree", MP, KVS2);

    err = curl_get(path, sock, buf, sizeof(buf));
    ASSERT_EQ(0, err);
    ASSERT_STREQ(exp, buf);
    ct_view_two_level = false;
    ct_view_two_kvsets = false;
    ct_view_do_nothing = true;

    MOCK_UNSET(ct_view, _cn_tree_view_create);
    MOCK_UNSET(ct_view, _cn_tree_view_destroy);

    MOCK_UNSET(kvset_view, _kvset_get_dgen);
    count = 0;
}

MTF_DEFINE_UTEST_PREPOST(kvdb_rest, t_curperf, test_pre, test_post)
{
    char   request[256];
    char   resp[1024];
    merr_t err;
    int    i, n;

    struct testcase {
        bool  success;
        char *query;
    } testcases[] = {

        { true, "" },
        { true, "xxx" }, /* tests the "verify path is exact" case */

        { true, "?prefix" },
        { true, "?prefix=" },
        { true, "?prefix=foo" },

        { true, "?seek" },
        { true, "?seek=" },
        { true, "?seek=foo" },

        { false, "?reverse" },
        { false, "?reverse=" },
        { false, "?reverse=3" },
        { false, "?reverse=x" },
        { true, "?reverse=0" },
        { true, "?reverse=1" },

        { false, "?count=" },
        { false, "?count=x" },
        { false, "?count=1x" },
        { false, "?count=99999999999" },
        { false, "?count=100000" },
        { true, "?count" },
        { true, "?count=1" },
        { true, "?count=100" },

        { true, "?prefix=foo&seek=foobar&reverse=1&count=4" },

    };

    for (i = 0; i < NELEM(testcases); i++) {

        const char *query = testcases[i].query;
        bool        expect_success = testcases[i].success;
        bool        success;

        n = snprintf(request, sizeof(request), "mpool/%s/kvs/%s/curperf%s", MP, KVS1, query);

        ASSERT_LT(n, sizeof(request));

        printf("\n");
        printf("testcase: %d\n", i);
        printf("request: %s\n", request);
        printf("expect: %s\n", expect_success ? "success" : "failure");

        memset(resp, 0, sizeof(resp));
        err = curl_get(request, sock, resp, sizeof(resp));

        printf("status: %ld\n--response\n%s--end-response\n", (long)err, resp);

        /* If curl failed, we have our status.
         * If curl succeeded, get status from response.
         */
        if (err)
            success = false;
        else
            success = (strstr(resp, "error:") == 0);

        ASSERT_EQ(expect_success, success);
    }
}

MTF_DEFINE_UTEST_PREPOST(kvdb_rest, kvdb_compact_test, test_pre, test_post)
{
    char   path[128];
    char   buf[4096] = { 0 };
    merr_t err;

    /* Put request */
    snprintf(path, sizeof(path), "mpool/%s/compact/request", MP);

    err = curl_put(path, sock, 0, 0, buf, sizeof(buf));
    ASSERT_EQ(0, err);

    err = curl_put(path, sock, 0, 0, buf, sizeof(buf));
    ASSERT_EQ(0, err);

    snprintf(path, sizeof(path), "mpool/%s/compact/cancel", MP);

    err = curl_put(path, sock, 0, 0, buf, sizeof(buf));
    ASSERT_EQ(0, err);

    snprintf(path, sizeof(path), "mpool/%s/compact/bob", MP);

    err = curl_put(path, sock, 0, 0, buf, sizeof(buf));
    ASSERT_EQ(0, err);

    /* Get status */
    snprintf(path, sizeof(path), "mpool/%s/compact/status", MP);
    err = curl_get(path, sock, buf, sizeof(buf));
    ASSERT_EQ(0, err);
}

MTF_END_UTEST_COLLECTION(kvdb_rest)
