/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>

#include <bsd/string.h>
#include <cjson/cJSON.h>

#include <mtf/framework.h>
#include <mock/api.h>
#include <mocks/mock_kvset_builder.h>

#include <hse/logging/logging.h>
#include <hse/util/parse_num.h>

#include <hse/limits.h>

#include <hse/ikvdb/kvs_rparams.h>
#include <hse/ikvdb/kvs_cparams.h>
#include <hse/ikvdb/kvset_builder.h>
#include <hse/ikvdb/limits.h>
#include <hse/ikvdb/cn.h>
#include <hse/ikvdb/cndb.h>

#include "cn/cn_tree.h"
#include "cn/cn_tree_create.h"
#include "cn/cn_tree_compact.h"
#include "cn/cn_tree_internal.h"
#include "cn/spill.h"
#include "cn/kcompact.h"
#include "cn/cn_metrics.h"
#include "cn/kvs_mblk_desc.h"
#include "cn/kv_iterator.h"
#include "cn/kvset.h"
#include "cn/route.h"
#include "cn/omf.h"
#include "cn/vgmap.h"

#include <dirent.h>

#define my_assert(condition)                                                                  \
    do {                                                                                      \
        int pain = !(condition);                                                              \
        if (pain) {                                                                           \
            fprintf(stderr, "%s:%d: assert(%s)\n", REL_FILE(__FILE__), __LINE__, #condition); \
            abort();                                                                          \
        }                                                                                     \
    } while (0)

#define VERBOSE_PER_FILE1 1
#define VERBOSE_PER_FILE2 2
#define VERBOSE_PER_KEY1 3
#define VERBOSE_PER_KEY2 4
#define VERBOSE_MAX 5

#define MAX_TEST_FILES 256

static struct test_params {
    /* Intialized once at start of program */
    char *test_filev[MAX_TEST_FILES];
    int   test_filec;
    int   verbose;

    /* Initialized with each new JSON file */
    cJSON *doc;
    char group[256];
    cJSON *out_kvset_node;
    int out_kvset_nkeys;
    cJSON *inp_kvset_nodev;
    int inp_kvset_nodec;
    int test_number;
    uint64_t horizon;
    bool drop_tombs;
    int fanout;

    /* Initialized with each mode (spill, kcompact, etc) */
    int pfx_len;
    int next_output_key;
    int next_output_val;

    /* Initialized when a new ptomb is encountered (spread mode only) */
    int  last_pt_key;
    uint64_t  last_pt_seq;
    int  pt_count;
} tp;

static void
search_dir(const char *path)
{
    struct dirent *ent;
    char *         dir_path;
    size_t         len;
    DIR *          dir;
    int            rc;

    dir = opendir(path);
    if (!dir) {
        fprintf(stderr, "Cannot open dir: %s\n", path);
        exit(1);
    }

    dir_path = malloc(PATH_MAX + 1);
    my_assert(dir_path);

    while (NULL != (ent = readdir(dir))) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
            continue;

        if (ent->d_type == DT_DIR) {
            rc = snprintf(dir_path, PATH_MAX, "%s/%s", path, ent->d_name);
            my_assert(rc <= PATH_MAX);
            search_dir(dir_path);
            continue;
        }

        if (ent->d_type != DT_REG)
            continue;

        if (!strcmp(ent->d_name, ".checkfiles.json"))
            continue;

        len = strlen(ent->d_name);
        if (len <= 4 || strcmp(ent->d_name + len - 5, ".json"))
            continue;

        if (tp.test_filec == MAX_TEST_FILES) {
            fprintf(stderr, "too many test files\n");
            exit(-1);
        }

        tp.test_filev[tp.test_filec] = 0;
        rc = asprintf(&tp.test_filev[tp.test_filec], "%s/%s", path, ent->d_name);
        my_assert(rc != -1);
        my_assert(tp.test_filev[tp.test_filec]);
        ++tp.test_filec;
    }

    free(dir_path);
    closedir(dir);
}

static void
get_test_files(const char *path)
{
    struct stat st;

    if (stat(path, &st)) {
        fprintf(stderr, "Cannot stat path: %s\n", path);
        exit(-1);
    }

    if (S_IFDIR == (st.st_mode & S_IFMT)) {
        search_dir(path);
        return;
    }

    if (S_IFREG == (st.st_mode & S_IFMT)) {
        tp.test_filev[tp.test_filec] = strdup(path);
        my_assert(tp.test_filev[tp.test_filec]);
        ++tp.test_filec;
        return;
    }

    fprintf(stderr, "Not a file or dir: %s\n", path);
    exit(-1);
}

static enum kmd_vtype
ydoc_node_as_vtype(cJSON *node)
{
    const char *str;

    str = cJSON_GetStringValue(node);

    if (!strcmp(str, "v"))
        return VTYPE_UCVAL;

    if (!strcmp(str, "z"))
        return VTYPE_ZVAL;

    if (!strcmp(str, "i"))
        return VTYPE_IVAL;

    if (!strcmp(str, "t"))
        return VTYPE_TOMB;

    if (!strcmp(str, "pt"))
        return VTYPE_PTOMB;

    my_assert(0);
    return -1;
}

static bool
ydoc_kvset_get_nth(
    cJSON *kvset_node,
    int nth,
    cJSON **key,
    cJSON **vec)
{
    cJSON *entry_node;

    entry_node = cJSON_GetArrayItem(kvset_node, nth);
    if (!entry_node)
        return true;
    my_assert(cJSON_IsArray(entry_node));

    /* Get key and list of values.  If no key or no values,
     * then assert due to invalid yaml document schema.
     *
     *  entry_node = [ key, [[seq,vtype,val],...] ]
     */

    *key = cJSON_GetArrayItem(entry_node, 0);
    my_assert(cJSON_IsString(*key));

    *vec = cJSON_GetArrayItem(entry_node, 1);
    my_assert(cJSON_IsArray(*vec));

    return false;
}

static void
process_json(void)
{
    cJSON *node, *node2;
    char *name;

    name = "_meta";
    node = cJSON_GetObjectItemCaseSensitive(tp.doc, name);
    my_assert(cJSON_IsObject(node));

    tp.horizon = 0;
    tp.drop_tombs = 0;
    tp.pfx_len = -1;
    tp.fanout = 4;

    node2 = cJSON_GetObjectItemCaseSensitive(node, "horizon");
    if (node2)
        tp.horizon = cJSON_GetNumberValue(node2);
    node2 = cJSON_GetObjectItemCaseSensitive(node, "drop_tombs");
    if (node2)
        tp.drop_tombs = cJSON_IsTrue(node2);
    node2 = cJSON_GetObjectItemCaseSensitive(node, "pfx_len");
    if (node2)
        tp.pfx_len = cJSON_GetNumberValue(node2);
    node2 = cJSON_GetObjectItemCaseSensitive(node, "fanout");
    if (node2)
        tp.fanout = cJSON_GetNumberValue(node2);

    node = cJSON_GetObjectItemCaseSensitive(tp.doc, "output_kvset");
    my_assert(cJSON_IsArray(node));

    tp.out_kvset_node = node;
    tp.out_kvset_nkeys = cJSON_GetArraySize(node);

    node = cJSON_GetObjectItemCaseSensitive(tp.doc, "input_kvsets");
    my_assert(cJSON_IsArray(node));

    tp.inp_kvset_nodev = node;
    tp.inp_kvset_nodec = cJSON_GetArraySize(node);
}

static void
load_json(struct mtf_test_info *lcl_ti)
{
    FILE *fp;
    struct stat st;
    int rc;
    char *buf;

    fp = fopen(tp.test_filev[tp.test_number], "rb");
    ASSERT_NE(fp, NULL);

    rc = fstat(fileno(fp), &st);
    ASSERT_NE(-1, rc);

    buf = malloc(st.st_size + 1);
    ASSERT_NE(NULL, buf);
    buf[st.st_size] = '\0';

    rc = fread(buf, st.st_size, 1, fp);
    ASSERT_EQ(1, rc);

    tp.doc = cJSON_ParseWithLength(buf, st.st_size);
    ASSERT_NE(NULL, tp.doc);

    free(buf);
    fclose(fp);
}

static bool
kvset_get_nth_key(
    cJSON *kvset_node,
    int nth,
    cJSON **key,
    uint *nvals_out)
{
    bool eof;
    cJSON *vec;

    eof = ydoc_kvset_get_nth(kvset_node, nth, key, &vec);
    if (!eof)
        *nvals_out = cJSON_GetArraySize(vec);

    return eof;
}

static bool
kvset_get_nth_val(
    cJSON *kvset_node,
    int nth_key,
    int nth_value,
    uint64_t *seq_out,
    enum kmd_vtype *vtype_out,
    const void **vdata_out,
    uint *vlen_out)
{
    bool eof;
    cJSON *key;
    cJSON *vec;
    cJSON *entry;

    eof = ydoc_kvset_get_nth(kvset_node, nth_key, &key, &vec);
    /* nth_key is expected to be in range. */
    my_assert(!eof);

    if (nth_value >= cJSON_GetArraySize(vec))
        return true;

    /* Values are stored as a list of lists;
     *   [ [ seq, vtype, value ], [ seq, vtype, value ], ... ]
     */
    my_assert(cJSON_IsArray(vec));
    entry = cJSON_GetArrayItem(vec, nth_value);
    my_assert(cJSON_IsArray(entry));
    *seq_out = cJSON_GetNumberValue(cJSON_GetArrayItem(entry, 0));
    *vtype_out = ydoc_node_as_vtype(cJSON_GetArrayItem(entry, 1));

    switch (*vtype_out) {
        case VTYPE_UCVAL: {
            cJSON *value = cJSON_GetArrayItem(entry, 2);
            my_assert(cJSON_IsString(value));
            *vdata_out = cJSON_GetStringValue(value);
            *vlen_out = strlen(*vdata_out);
            if (*vlen_out < CN_SMALL_VALUE_THRESHOLD)
                *vtype_out = VTYPE_IVAL;
            break;
        }
        default:
            *vdata_out = 0;
            *vlen_out = 0;
    }

    return eof;
}

static bool
kvset_get_nth(
    cJSON *kvset_node,
    int nth,
    const void **key,
    uint *key_len,
    void **val,
    uint *val_len)
{
    cJSON *key_node;
    cJSON *value_nodes;
    cJSON *value_node;
    bool eof;

    eof = ydoc_kvset_get_nth(kvset_node, nth, &key_node, &value_nodes);
    if (!eof) {
        my_assert(cJSON_IsString(key_node));
        *key = cJSON_GetStringValue(key_node);
        *key_len = strlen(*key);

        value_node = cJSON_GetArrayItem(cJSON_GetArrayItem(value_nodes, 0), 2);
        my_assert(cJSON_IsString(value_node));
        *val = cJSON_GetStringValue(value_node);
        *val_len = strlen(*val);
    }

    return eof;
}

/*----------------------------------------------------------------
 * Handle kvset_builder_add_* functions to get key/value pairs
 * and verify them.
 */
static merr_t
_kvset_builder_add_key(struct kvset_builder *builder, const struct key_obj *kobj)
{
    cJSON *key;
    uint ref_nvals;
    bool eof;
    uint8_t kdata[HSE_KVS_KEY_LEN_MAX];
    uint klen;

    key_obj_copy(kdata, sizeof(kdata), &klen, kobj);

    if (tp.verbose >= VERBOSE_PER_KEY1)
        printf("add_key, expect key#%u %.*s\n", tp.next_output_key, klen, (char *)kdata);

    VERIFY_TRUE_RET(klen > 0, __LINE__);
    VERIFY_TRUE_RET(kdata != NULL, __LINE__);

    /* Get the next reference and compare */
    VERIFY_TRUE_RET(tp.next_output_key < tp.out_kvset_nkeys, __LINE__);

    eof = kvset_get_nth_key(
        tp.out_kvset_node, tp.next_output_key, &key, &ref_nvals);
    VERIFY_TRUE_RET(!eof, __LINE__);

    /* check for same number of values */
    VERIFY_TRUE_RET(tp.next_output_val == ref_nvals, __LINE__);

    /* check for same key */
    VERIFY_TRUE_RET(klen == strlen(cJSON_GetStringValue(key)), __LINE__);
    VERIFY_TRUE_RET(!memcmp(kdata, cJSON_GetStringValue(key), klen), __LINE__);

    /* reset for next key */
    tp.next_output_key++;
    tp.next_output_val = 0;

    return 0;
}

static void
_kvset_builder_add_val_internal(
    struct kvset_builder *self,
    uint64_t              seq,
    enum kmd_vtype        vtype,
    const void *          vdata,
    uint                  vlen)
{
    bool           ref_eof;
    uint64_t       ref_seq = 0;
    enum kmd_vtype ref_vtype = VTYPE_UCVAL;
    const void *   ref_vdata = NULL;
    uint           ref_vlen = 0;

    ref_eof = kvset_get_nth_val(
        tp.out_kvset_node,
        tp.next_output_key,
        tp.next_output_val,
        &ref_seq,
        &ref_vtype,
        &ref_vdata,
        &ref_vlen);

    if (tp.verbose >= VERBOSE_PER_KEY1)
        printf(
            "add_val, expect key#%u val#%d:%s",
            tp.next_output_key,
            tp.next_output_val,
            ref_eof ? "\n" : " ");
    if (tp.verbose >= VERBOSE_PER_KEY1) {
        char *tag = "?";
        switch (ref_vtype) {
            case VTYPE_UCVAL:
                tag = "v";
                break;
            case VTYPE_CVAL:
                tag = "c";
                break;
            case VTYPE_ZVAL:
                tag = "z";
                break;
            case VTYPE_IVAL:
                tag = "i";
                break;
            case VTYPE_TOMB:
                tag = "t";
                break;
            case VTYPE_PTOMB:
                tag = "pt";
                break;
        }
        printf( "%lu %s %.*s\n", (ulong)ref_seq, tag, ref_vlen,
            ref_vdata ? (char *)ref_vdata : "");
    }

    if (vtype != VTYPE_PTOMB) {
        /* If the following checks fail, then more values have been
         * generated than were expected.
         */
        VERIFY_TRUE(!ref_eof);
        my_assert(!ref_eof);
    }

    VERIFY_EQ(seq, ref_seq);
    VERIFY_EQ(vtype, ref_vtype);
    if (vtype == VTYPE_UCVAL || vtype == VTYPE_IVAL) {
        int cmp;

        VERIFY_EQ(vlen, ref_vlen);
        cmp = memcmp(vdata, ref_vdata, vlen);
        VERIFY_EQ(0, cmp);
    }

    tp.next_output_val++;
}

static merr_t
_kvset_builder_add_vref(
    struct kvset_builder *self,
    uint64_t              seq,
    uint                  vbidx_kvset_node,
    uint                  vboff_nth_key,
    uint                  vlen_nth_val,
    uint                  complen)
{
    uint64_t tmp_seq;
    enum kmd_vtype vtype;
    const void *vdata;
    uint vlen;
    cJSON *kvset_node;
    uint nth_key, nth_val;
    bool eof;

    /* Unpack data from vref:
     *   vbidx == kvset node
     *   vboff == nth_key
     *   vblen == nth_val
     *
     * See also _kvset_iter_next_vref(), which packs this data.
     */
    kvset_node = cJSON_GetArrayItem(tp.inp_kvset_nodev, vbidx_kvset_node);
    nth_key = vboff_nth_key;
    nth_val = vlen_nth_val;

    eof = kvset_get_nth_val(kvset_node, nth_key, nth_val, &tmp_seq, &vtype, &vdata, &vlen);
    my_assert(!eof);

    _kvset_builder_add_val_internal(self, seq, vtype, vdata, vlen);
    return 0;
}

merr_t
_kvset_builder_add_val(
    struct kvset_builder *  self,
    const struct key_obj   *kobj,
    const void *            vdata,
    uint                    vlen,
    uint64_t                seq,
    uint                    complen)
{
    enum kmd_vtype vtype;

    if (vdata == HSE_CORE_TOMB_REG)
        vtype = VTYPE_TOMB;
    else if (vdata == HSE_CORE_TOMB_PFX)
        vtype = VTYPE_PTOMB;
    else if (!vdata || !vlen)
        vtype = VTYPE_ZVAL;
    else if (!vdata || vlen < CN_SMALL_VALUE_THRESHOLD)
        vtype = VTYPE_IVAL;
    else
        vtype = VTYPE_UCVAL;

    _kvset_builder_add_val_internal(self, seq, vtype, vdata, vlen);
    return 0;
}

static merr_t
_kvset_builder_add_nonval(struct kvset_builder *self, uint64_t seq, enum kmd_vtype vtype)
{
    _kvset_builder_add_val_internal(self, seq, vtype, 0, 0);
    return 0;
}

/*----------------------------------------------------------------
 * Iterator
 */
struct kv_spill_test_kvi {
    struct kv_iterator  kvi;
    struct test_params *test;
    cJSON *kvset_node;
    uint32_t src;
    uint32_t cursor;
};

static struct kvset *
_kvset_iter_kvset_get(struct kv_iterator *kvi)
{
    return (struct kvset *)container_of(kvi, struct kv_spill_test_kvi, kvi);
}

static merr_t
_kvset_iter_next_key(struct kv_iterator *kvi, struct key_obj *kobj, struct kvset_iter_vctx *vc)
{
    struct kv_spill_test_kvi *iter = container_of(kvi, typeof(*iter), kvi);

    void *vdata;
    uint  vlen;
    uint  nth_key = iter->cursor;

    kobj->ko_pfx = 0;
    kobj->ko_pfx_len = 0;
    kvi->kvi_eof = kvset_get_nth(iter->kvset_node, nth_key, &kobj->ko_sfx, &kobj->ko_sfx_len,
        &vdata, &vlen);
    if (kvi->kvi_eof) {
        if (tp.verbose >= VERBOSE_PER_KEY2)
            printf("iter_next_key src %d ent %d EOF\n", iter->src, nth_key);
        return 0;
    }
    ++iter->cursor;

    if (tp.verbose >= VERBOSE_PER_KEY2)
        printf(
            "iter_next_key src %d ent %d kdata %.*s\n",
            iter->src,
            nth_key,
            (int)kobj->ko_sfx_len,
            (char *)kobj->ko_sfx);

    /* Pack data into kvset_iter_vctx:
     *   vc->kmd   == kvset node
     *   vc->nvals == unused
     *   vc->off   == key in kvset node
     *   vc->next  == which value
     *
     * See also _kvset_iter_next_vref, which unpacks this data.
     */
    vc->kmd = (void *)iter->kvset_node;
    vc->nvals = 0;
    vc->off = nth_key;
    vc->next = 0;
    /* Spill is always called with a node_dgen of 0, set the kv-pair's dgen to something larger than 0.
     */
    vc->dgen = 10;
    return 0;
}

static bool
_kvset_iter_next_vref(
    struct kv_iterator *    kvi,
    struct kvset_iter_vctx *vc,
    uint64_t *              seq,
    enum kmd_vtype *        vtype,
    uint *                  vbidx,
    uint *                  vboff,
    const void **           vdata,
    uint *                  vlen_out,
    uint *                  clen_out)
{
    /* Unpack data from kvset_iter_vctx:
     *   vc->kmd   == kvset node
     *   vc->nvals == unused
     *   vc->off   == key in kvset node
     *   vc->next  == which value
     *
     * See also _kvset_iter_next_key(), which packs this data.
     */
    cJSON *kvset_node = (cJSON *)vc->kmd;
    int nth_key = vc->off;
    int nth_val = vc->next;

    bool        eof;
    const void *lvdata;
    uint        vlen;

    eof = kvset_get_nth_val(kvset_node, nth_key, nth_val, seq, vtype, &lvdata, &vlen);
    if (eof)
        return false;

    switch (*vtype) {
        case VTYPE_UCVAL:
            /* Pack data into vref:
             *   vbidx == kvset node
             *   vboff == nth_key
             *   vlen_out == nth_val
             * See also _kvset_builder_add_vref(), which unpacks this data.
             */
            for (int i = 0; i < cJSON_GetArraySize(tp.inp_kvset_nodev); i++) {
                if (cJSON_GetArrayItem(tp.inp_kvset_nodev, i) == kvset_node) {
                    *vbidx = i;
                    break;
                }
            }

            *vboff = nth_key;
            *vlen_out = nth_val;
            break;
        case VTYPE_IVAL:
        case VTYPE_ZVAL:
        case VTYPE_TOMB:
        case VTYPE_PTOMB:
            *vdata = (void *)lvdata;
            *vlen_out = vlen;
            break;
        case VTYPE_CVAL:
            /* not used by this test */
            assert(0);
            break;
    }

    /* bump value index for next call */
    ++vc->next;
    return true;
}

static merr_t
_kvset_iter_val_get(
    struct kv_iterator *    kvi,
    struct kvset_iter_vctx *vc,
    enum kmd_vtype          vtype,
    uint                    vbidx,
    uint                    vboff,
    const void **           vdata_out,
    uint *                  vlen_out,
    uint *                  clen_out)
{
    /*
     * Unpack data from kvset_iter_vctx:
     *   vbidx     == kvset node
     *   vboff     == key in kvset node
     *   *vlen_out == which value
     * See _kvset_iter_val_get() which supplies the location of value
     * See also _kvset_iter_next_key(), which packs this data.
     */
    cJSON* kvset_node;
    int nth_key;
    int nth_val;
    uint64_t seq;

    const void *vdata;
    bool        end;

    /* Need to handle VTYPE_UCVAL case. The rest are already provided by
     * _kvset_iter_next_vref.
     */

    if (vtype == VTYPE_UCVAL) {
        kvset_node = cJSON_GetArrayItem(tp.inp_kvset_nodev, vbidx);
        nth_key = vboff;
        nth_val = *vlen_out;

        end = kvset_get_nth_val(kvset_node, nth_key, nth_val, &seq, &vtype, &vdata, vlen_out);
        if (end)
            return 0;
    }

    switch (vtype) {
        case VTYPE_CVAL:
            /* not used by this test */
            assert(0);
            break;
        case VTYPE_UCVAL:
            *vdata_out = (void *)vdata;
            return 0;
        case VTYPE_IVAL:
            return 0;
        case VTYPE_ZVAL:
            *vdata_out = 0;
            *vlen_out = 0;
            return 0;
        case VTYPE_TOMB:
            *vdata_out = HSE_CORE_TOMB_REG;
            *vlen_out = 0;
            return 0;
        case VTYPE_PTOMB:
            *vdata_out = HSE_CORE_TOMB_PFX;
            *vlen_out = 0;
            return 0;
    }

    my_assert(false);
    return merr(EBUG);
}

void
kv_spill_test_kvi_release(struct kv_iterator *kvi)
{
    free(container_of(kvi, struct kv_spill_test_kvi, kvi));
}

/*----------------------------------------------------------------
 * Kvset
 */
static uint64_t
_kvset_get_dgen(const struct kvset *kvset)
{
    return tp.inp_kvset_nodec - 1 - ((struct kv_spill_test_kvi *)kvset)->src;
}

struct kv_iterator_ops kvi_ops = { .kvi_release = kv_spill_test_kvi_release };

static bool
_kvset_cursor_next(struct element_source *es, void **element)
{
    struct kv_iterator *kvi = kvset_cursor_es_h2r(es);
    struct cn_kv_item * kv = &kvi->kvi_kv;

    *element = 0;

    _kvset_iter_next_key(kvi, &kv->kobj, &kv->vctx);
    if (kvi->kvi_eof)
        return false;

    kv->src = es;
    *element = &kvi->kvi_kv;

    return true;
}

static merr_t
kv_spill_test_kvi_create(
    struct kv_iterator ** kvi_out,
    struct test_params *  tp,
    uint32_t              src,
    struct mtf_test_info *lcl_ti)
{
    struct kv_spill_test_kvi *iter =
        (struct kv_spill_test_kvi *)calloc(1, sizeof(struct kv_spill_test_kvi));
    if (!iter)
        return merr(ENOMEM);

    my_assert(src < tp->inp_kvset_nodec);

    iter->test = tp;
    iter->src = src;
    iter->kvset_node = cJSON_GetArrayItem(tp->inp_kvset_nodev, src);
    iter->cursor = 0;

    iter->kvi.kvi_ops = &kvi_ops;
    iter->kvi.kvi_es = es_make(_kvset_cursor_next, NULL, NULL);

    *kvi_out = &iter->kvi;

    return 0;
}

#define MODE_SPILL 0
#define MODE_KCOMPACT 1

static struct cn_compaction_work *
init_work(
    struct cn_compaction_work *w,
    struct mpool *             ds,
    struct kvs_rparams *       rp,
    struct cn_tree *           tree,
    uint64_t                   horizon,
    uint                       num_sources,
    struct kv_iterator **      sources,
    uint                       shift,
    uint                       pfx_len,
    struct perfc_set *         pc,
    atomic_int                *cancel,
    uint                       num_outputs,
    bool                       drop_tombs,
    struct kvset_mblocks *     outputs,
    struct cn_tree_node **     output_nodev,
    uint64_t                  *kvsetidv,
    struct kvset_vblk_map *    vbmap,
    struct vgmap             **vgmap)
{
    memset(w, 0, sizeof(*w));

    w->cw_mp = ds;
    w->cw_tree = tree;
    w->cw_rp = rp;
    w->cw_cp = tree ? cn_tree_get_cparams(tree) : 0;
    w->cw_pfx_len = pfx_len;
    w->cw_horizon = horizon;
    w->cw_kvset_cnt = num_sources;
    w->cw_inputv = sources;
    w->cw_pc = pc;
    w->cw_cancel_request = cancel;
    w->cw_outc = num_outputs;
    w->cw_drop_tombs = drop_tombs;
    w->cw_outv = outputs;
    w->cw_output_nodev = output_nodev;
    w->cw_kvsetidv = kvsetidv;

    if (vgmap) {
        w->cw_input_vgroups = (*vgmap)->nvgroups;
        w->cw_vgmap = vgmap;
    }

    if (vbmap)
        w->cw_vbmap = *vbmap;

    return w;
}

static void
run_testcase(struct mtf_test_info *lcl_ti, int mode, const char *info)
{
    merr_t err;
    uint32_t i;
    uint32_t iterc;
    uint eklen = 0;
    uint32_t shift = 0;
    atomic_int cancel;
    struct spillctx *sctx;
    int pfx_len = tp.pfx_len;
    struct subspill subspill;
    struct kv_iterator **iterv;
    struct cn_compaction_work w;
    uint64_t kvsetidv[tp.fanout];
    struct kvset_mblocks outputs[tp.fanout];
    unsigned char ekey[HSE_KVS_KEY_LEN_MAX];
    struct mpool *ds = (struct mpool *)lcl_ti;
    struct cn_tree_node *output_nodev[tp.fanout];
    struct kvs_rparams   rp = kvs_rparams_defaults();

    if (tp.verbose >= VERBOSE_PER_FILE2)
        printf("Mode: %s\n", info);

    iterc = tp.inp_kvset_nodec;
    if (iterc == 0)
        return;

    atomic_set(&cancel, 0);

    tp.next_output_key = 0;
    tp.last_pt_key = -1;

    /* Create source kvset iterators (one for each input kvset) */
    iterv = (struct kv_iterator **)calloc(iterc, sizeof(*iterv));
    ASSERT_TRUE(iterv != NULL);

    for (i = 0; i < iterc; i++)
        err = kv_spill_test_kvi_create(&iterv[i], &tp, i, lcl_ti);

    memset(outputs, 0, sizeof(outputs));
    memset(output_nodev, 0, sizeof(output_nodev));

    if (mode == MODE_SPILL) {
        struct cn_tree *tree;
        struct kvdb_health    health;

        struct kvs_cparams cp = {
            .pfx_len = tp.pfx_len,
        };

        err = cn_tree_create(&tree, 0, &cp, &health, &rp);
        ASSERT_EQ(err, 0);
        ASSERT_NE(tree, NULL);

        cn_tree_setup(tree, NULL, NULL, &rp, NULL, 1234, 0);

        for (i = 0; i < tp.fanout; i++) {
            struct cn_tree_node *tn;
            char ekbuf[HSE_KVS_KEY_LEN_MAX];
            size_t eklen;

            tn = cn_node_alloc(tree, i + 1);
            ASSERT_NE(0, tn);

            if (i < tp.fanout - 1)
                eklen = snprintf(ekbuf, sizeof(ekbuf), "a.%08d", i);
            else {
                eklen = sizeof(ekbuf);
                memset(ekbuf, 0xff, sizeof(ekbuf));
            }
            tn->tn_route_node = route_map_insert(tree->ct_route_map, tn, ekbuf, eklen);
            list_add_tail(&tn->tn_link, &tree->ct_nodes);
        }

        init_work(
            &w,
            ds,
            &rp,
            tree,
            tp.horizon,
            iterc,
            iterv,
            shift,
            pfx_len,
            0,
            &cancel,
            tp.fanout,
            tp.drop_tombs,
            outputs,
            output_nodev,
            kvsetidv,
            NULL,
            NULL);

        w.cw_action = CN_ACTION_SPILL;
        w.cw_cp = &cp;

        err = cn_spill_create(&w, &sctx);
        ASSERT_EQ(0, err);

        while (1) {
            struct route_node *rtn;

            rtn = route_map_lookupGT(tree->ct_route_map, ekey, eklen);
            if (!rtn)
                break;

            route_node_keycpy(rtn, ekey, sizeof(ekey), &eklen);

            err = cn_subspill(&subspill, sctx, 0, 0, ekey, eklen);
            ASSERT_EQ(0, err);
        }

        cn_spill_destroy(sctx);
        cn_tree_destroy(tree);
    } else {
        /* kcompact */
        struct kvset_vblk_map vbmap;
        struct vgmap *vgmap, *vgmap2;
        uint64_t *blkv = mapi_safe_malloc(sizeof(*blkv) * iterc);
        uint32_t *map = mapi_safe_malloc(sizeof(*map) * iterc);

        ASSERT_TRUE(blkv != 0);
        ASSERT_TRUE(map != 0);

        memset(&vbmap, 0, sizeof(vbmap));
        vbmap.vbm_blkv = mapi_safe_malloc(sizeof(*vbmap.vbm_blkv) * iterc);

        for (i = 0; i < iterc; i++) {
            vbmap.vbm_blkv[i] = 1000 + i;
            map[i] = 0;
        }
        vbmap.vbm_map = map;
        vbmap.vbm_blkc = iterc;
        vbmap.vbm_mapc = iterc;
        vbmap.vbm_used = 0;
        vbmap.vbm_waste = 0;

        vgmap = vgmap_alloc(1);
        ASSERT_NE(vgmap, NULL);

        init_work(
            &w,
            ds,
            &rp,
            NULL,
            tp.horizon,
            iterc,
            iterv,
            0,
            pfx_len,
            0,
            &cancel,
            1,
            tp.drop_tombs,
            outputs,
            output_nodev,
            kvsetidv,
            &vbmap,
            &vgmap);

        w.cw_action = CN_ACTION_COMPACT_K;

        vgmap2 = vgmap;
        err = cn_kcompact(&w);
        ASSERT_EQ(err, 0);

        mapi_safe_free(vbmap.vbm_blkv);
        mapi_safe_free(blkv);
        mapi_safe_free(map);

        vgmap_free(vgmap2);
    }

    /* Check results */
    ASSERT_EQ(tp.next_output_key, tp.out_kvset_nkeys);

    /* Cleanup */
    for (i = 0; i < iterc; i++)
        kv_iterator_release(&iterv[i]);
    free(iterv);
}

static void
setup_tcase(struct mtf_test_info *lcl_ti)
{
    load_json(lcl_ti);
    process_json();
}

static void
teardown_tcase(struct mtf_test_info *lcl_ti)
{
    cJSON_Delete(tp.doc);
    tp.doc = NULL;
}

static void
run_all_tcases(struct mtf_test_info *lcl_ti)
{
    for (int i = 0; i < tp.test_filec; i++) {
        tp.test_number = i;

        if (tp.verbose >= VERBOSE_PER_FILE1)
            printf("Test File: %s\n", tp.test_filev[i]);

        setup_tcase(lcl_ti);

        tp.pfx_len = tp.pfx_len >= 0 ? tp.pfx_len : 0;
        run_testcase(lcl_ti, MODE_SPILL, "spill");

        tp.pfx_len = tp.pfx_len >= 0 ? tp.pfx_len : 0;
        run_testcase(lcl_ti, MODE_KCOMPACT, "kcompact");

        tp.pfx_len = tp.pfx_len >= 0 ? tp.pfx_len : 3;
        run_testcase(lcl_ti, MODE_SPILL, "spill with prefix");

        teardown_tcase(lcl_ti);
    }
}

#define HELP                                                        \
    "Usage: merge_test <path> [ options ]\n"                        \
    "\n"                                                            \
    "This utility runs spill and compaction tests.  Each test\n"    \
    "case is defined by a single YAML file.  If <path> is a\n"      \
    "directory, recursively search for YAML files in given\n"       \
    "matching <path>/*.yml.  If <path> is a file, assume it is a\n" \
    "YAML file and run just that one test case.\n"                  \
    "\n"                                                            \
    "Options:\n"                                                    \
    "  -H       // show help\n"                                     \
    "  -q       // be quiet\n"                                      \
    "  -v       // be verbose\n"                                    \
    "  -v -v    // be more verbose\n"                               \
    "  -V       // max verbosity\n"

static void
help(FILE *fp, int code)
{
    fprintf(fp, "%s", HELP);
    exit(code);
}

int
test_collection_setup(struct mtf_test_info *info)
{
    int    argc = info->ti_coll->tci_argc;
    char **argv = info->ti_coll->tci_argv;
    int    idx = info->ti_coll->tci_optind;
    char * file_path = 0;
    int    i;

    tp.verbose = VERBOSE_PER_FILE1;

    for (i = idx; i < argc; i++) {
        if (!strcmp(argv[i], "-H"))
            help(stdout, 0);
        else if (!strcmp(argv[i], "-q"))
            tp.verbose = 0;
        else if (!strcmp(argv[i], "-v"))
            tp.verbose++;
        else if (!strcmp(argv[i], "-V"))
            tp.verbose = 100;
        else if (*argv[i] == '-')
            help(stderr, 1);
        else if (file_path)
            help(stderr, 1);
        else
            file_path = argv[i];
    }

    if (!file_path)
        help(stderr, 1);

    get_test_files(file_path);

    return 0;
}

int
test_collection_teardown(struct mtf_test_info *info)
{
    int i;

    for (i = 0; i < tp.test_filec; i++)
        free(tp.test_filev[i]);
    return 0;
}

int
test_prehook(struct mtf_test_info *info)
{
    /* Install the generic kvset builder mock. */
    mock_kvset_builder_set();

    /* We want to override some functions from the generic mock using
     * MOCK_SET. For each such function, we must use mapi_inject_unset()
     * to remove generic mock or else the MOCK_SET will not take effect.
     */
    mapi_inject_unset(mapi_idx_kvset_builder_add_key);
    mapi_inject_unset(mapi_idx_kvset_builder_add_val);
    mapi_inject_unset(mapi_idx_kvset_builder_add_nonval);
    mapi_inject_unset(mapi_idx_kvset_builder_add_vref);

    MOCK_SET(kvset_builder, _kvset_builder_add_key);
    MOCK_SET(kvset_builder, _kvset_builder_add_val);
    MOCK_SET(kvset_builder, _kvset_builder_add_nonval);
    MOCK_SET(kvset_builder, _kvset_builder_add_vref);

    /* Install kvset iterator mocks */
    MOCK_SET(kvset, _kvset_iter_next_key);
    MOCK_SET(kvset, _kvset_iter_val_get);
    MOCK_SET(kvset, _kvset_iter_next_vref);
    MOCK_SET(kvset, _kvset_iter_kvset_get);

    /* Install kvset mocks */
    MOCK_SET(kvset_view, _kvset_get_dgen);

    /* Neuter the following APIs */
    mapi_inject_ptr(mapi_idx_cn_tree_get_cn, NULL);
    mapi_inject(mapi_idx_kvset_builder_set_merge_stats, 0);
    mapi_inject(mapi_idx_cndb_kvsetid_mint, 1);
    mapi_inject(mapi_idx_cn_tree_get_cndb, 0);

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(spill_test_col, test_collection_setup, test_collection_teardown);

MTF_DEFINE_UTEST_PRE(spill_test_col, spill_test, test_prehook)
{
    run_all_tcases(lcl_ti);
}

MTF_END_UTEST_COLLECTION(spill_test_col)
