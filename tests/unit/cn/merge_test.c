/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mock/api.h>
#include <mocks/mock_kvset_builder.h>

#include <hse_util/logging.h>
#include <hse_util/parse_num.h>

#include <hse/limits.h>

#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/cndb.h>

#include <cn/cn_tree.h>
#include <cn/cn_tree_create.h>
#include <cn/cn_tree_compact.h>
#include <cn/cn_tree_internal.h>
#include <cn/spill.h>
#include <cn/kcompact.h>
#include <cn/cn_metrics.h>
#include <cn/kvs_mblk_desc.h>
#include <cn/kv_iterator.h>
#include <cn/kvset.h>
#include <cn/route.h>
#include <cn/omf.h>

#include <yaml.h>

#include <dirent.h>

#define my_assert(condition)                                                        \
    do {                                                                            \
        int pain = !(condition);                                                    \
        if (pain) {                                                                 \
            fprintf(stderr, "%s:%d: assert(%s)\n", __FILE__, __LINE__, #condition); \
            abort();                                                                \
        }                                                                           \
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

    /* Initialized with each new yaml file */
    yaml_document_t doc;
    char            group[256];
    int             out_kvset_node;
    int             out_kvset_nkeys;
    int *           inp_kvset_nodev;
    int             inp_kvset_nodec;
    int             test_number;
    u64             horizon;
    bool            drop_tombs;
    int             fanout;

    /* Initialized with each mode (spill, kcompact, etc) */
    int pfx_len;
    int next_output_key;
    int next_output_val;

    /* Initialized when a new ptomb is encountered (spread mode only) */
    int  last_pt_key;
    u64  last_pt_seq;
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

        if (!strcmp(ent->d_name, ".checkfiles.yml"))
            continue;

        len = strlen(ent->d_name);
        if (len <= 4 || strcmp(ent->d_name + len - 4, ".yml"))
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

static yaml_node_t *
ydoc_node(yaml_document_t *doc, int nx, yaml_node_type_t type)
{
    yaml_node_t *node;

    node = yaml_document_get_node(doc, nx);
    my_assert(node);
    if (type)
        my_assert(type == node->type);
    return node;
}

static yaml_node_type_t
ydoc_node_type(yaml_document_t *doc, int nx)
{
    return ydoc_node(doc, nx, 0)->type;
}

static const char *
ydoc_node_type_str(yaml_document_t *doc, int nx)
{
    switch (ydoc_node_type(doc, nx)) {
        case YAML_NO_NODE:
            break;
        case YAML_MAPPING_NODE:
            return "<map>";
        case YAML_SCALAR_NODE:
            return "<scalar>";
        case YAML_SEQUENCE_NODE:
            return "<sequence>";
    }
    return "<unknown_node_type>";
}

static void
ydoc_node_as_map(yaml_document_t *doc, int map_node, yaml_node_pair_t **vec, int *veclen)
{
    yaml_node_t *node;

    node = ydoc_node(doc, map_node, YAML_MAPPING_NODE);
    *vec = node->data.mapping.pairs.start;
    *veclen = node->data.mapping.pairs.top - *vec;
}

static void
ydoc_node_as_seq(yaml_document_t *doc, int seq_node, yaml_node_item_t **vec, int *veclen)
{
    yaml_node_t *node;

    node = ydoc_node(doc, seq_node, YAML_SEQUENCE_NODE);
    *vec = node->data.sequence.items.start;
    *veclen = node->data.sequence.items.top - *vec;
}

static const char *
ydoc_node_as_str(yaml_document_t *doc, int scalar_node, int *len)
{
    yaml_node_t *node;

    node = ydoc_node(doc, scalar_node, YAML_SCALAR_NODE);
    if (len)
        *len = node->data.scalar.length;
    my_assert(node->data.scalar.value);
    return (const char *)node->data.scalar.value;
}

static u64
ydoc_node_as_u64(yaml_document_t *doc, int scalar_node)
{
    const char *str;
    int         err;
    u64         result = 0;

    str = ydoc_node_as_str(doc, scalar_node, 0);
    err = parse_u64(str, &result);
    my_assert(!err);
    return result;
}

static int
ydoc_node_as_int(yaml_document_t *doc, int scalar_node)
{
    const char *str;
    int         err;
    int         result = 0;

    str = ydoc_node_as_str(doc, scalar_node, 0);
    err = parse_s32(str, &result);
    my_assert(!err);
    return result;
}

static bool
ydoc_node_as_bool(yaml_document_t *doc, int scalar_node)
{
    const char *str;

    str = ydoc_node_as_str(doc, scalar_node, 0);
    return (!strcasecmp(str, "true") || !strcasecmp(str, "yes") || !strcasecmp(str, "1"));
}

static enum kmd_vtype
ydoc_node_as_vtype(yaml_document_t *doc, int scalar_node)
{
    const char *str;

    str = ydoc_node_as_str(doc, scalar_node, 0);

    if (!strcmp(str, "v"))
        return vtype_val;

    if (!strcmp(str, "z"))
        return vtype_zval;

    if (!strcmp(str, "i"))
        return vtype_ival;

    if (!strcmp(str, "t"))
        return vtype_tomb;

    if (!strcmp(str, "pt"))
        return vtype_ptomb;

    my_assert(0);
    return -1;
}

static int
ydoc_seq_len(yaml_document_t *doc, int node)
{
    int               veclen;
    yaml_node_item_t *vec;

    ydoc_node_as_seq(doc, node, &vec, &veclen);
    return veclen;
}

/*
 * Given document node @map_node of type YAML_MAPPING_NODE, Return @value_node
 * where (@key_node, @value_node) is in the map defined by @map_node, and the
 * scalar value of key_node is @needle.  If no such pair exists, return 0
 * (which is an invalid node index).
 */
static int
ydoc_map_lookup(yaml_document_t *doc, int map_node, const char *needle)
{
    yaml_node_pair_t *vec;
    int               veclen, i;
    const char *      key;

    ydoc_node_as_map(doc, map_node, &vec, &veclen);
    for (i = 0; i < veclen; i++) {
        key = ydoc_node_as_str(doc, vec[i].key, 0);
        if (!strcmp(needle, key))
            return vec[i].value;
    }
    return 0;
}

static bool
ydoc_map_get_nth(yaml_document_t *doc, int map_node, int nth, const char **key, int *value_node)
{
    yaml_node_pair_t *vec;
    int               cnt;

    ydoc_node_as_map(doc, map_node, &vec, &cnt);
    if (nth < 0 || nth >= cnt)
        return false;
    *key = ydoc_node_as_str(doc, vec[nth].key, 0);
    *value_node = vec[nth].value;
    return true;
}

static bool
ydoc_seq_get_nth(yaml_document_t *doc, int seq_node, int nth, int *item_node)
{
    yaml_node_item_t *vec;
    int               veclen;

    ydoc_node_as_seq(doc, seq_node, &vec, &veclen);
    if (nth < 0 || nth >= veclen)
        return false;
    *item_node = vec[nth]; /* yaml_node_item_t is an int */
    return true;
}

static void
ydoc_map_print(yaml_document_t *doc, const char *prefix, int map_node)
{
    const char *key;
    const char *val;
    int         i, val_node;

    for (i = 0; ydoc_map_get_nth(doc, map_node, i, &key, &val_node); i++) {
        if (ydoc_node_type(doc, val_node) == YAML_SCALAR_NODE)
            val = ydoc_node_as_str(doc, val_node, 0);
        else
            val = ydoc_node_type_str(doc, val_node);
        printf("%s.%s = %s\n", prefix, key, val);
    }
}

static bool
ydoc_kvset_get_nth(
    yaml_document_t *  doc,
    int                kvset_node,
    int                nth,
    const char **      kdata,
    int *              klen,
    yaml_node_item_t **vec,
    int *              veclen)
{
    int  key_node;
    int  entry_node;
    int  values_node;
    bool found;

    /* no error if nth is out of range, just return false */
    if (!ydoc_seq_get_nth(doc, kvset_node, nth, &entry_node))
        return false;

    /* Get key and list of values.  If no key or no values,
     * then assert due to invalid yaml document schema.
     *
     *  entry_node = [ key, [[seq,vtype,val],...] ]
     */
    found = ydoc_seq_get_nth(doc, entry_node, 0, &key_node);
    my_assert(found);

    *kdata = ydoc_node_as_str(doc, key_node, klen);
    my_assert(*kdata);

    found = ydoc_seq_get_nth(doc, entry_node, 1, &values_node);
    my_assert(found);

    ydoc_node_as_seq(doc, values_node, vec, veclen);
    my_assert(*veclen > 0);

    return true;
}

static void
ydoc_kvset_print(yaml_document_t *doc, int kvset_node, const char *prefix)
{
    const char *      kdata;
    int               klen;
    yaml_node_item_t *values, *value;
    int               i, j, nvals, cnt;
    int               nkeys;

    nkeys = ydoc_seq_len(doc, kvset_node);

    printf("%s: start: %d keys\n", prefix, nkeys);
    i = 0;
    while (ydoc_kvset_get_nth(doc, kvset_node, i, &kdata, &klen, &values, &nvals)) {

        printf("%s: key[%d]=%s\n", prefix, i, kdata);
        for (j = 0; j < nvals; ++j) {
            ydoc_node_as_seq(doc, values[j], &value, &cnt);
            printf(
                "%s:   v[%d]=[ %s, %s, %s ]\n",
                prefix,
                j,
                ydoc_node_as_str(doc, value[0], 0),
                ydoc_node_as_str(doc, value[1], 0),
                ydoc_node_as_str(doc, value[2], 0));
        }
        ++i;
    }
}

static void
print_meta(void)
{
    yaml_document_t *doc = &tp.doc;
    int              root_node = 1;
    int              node;
    const char *     key = "_meta";

    node = ydoc_map_lookup(doc, root_node, key);
    my_assert(node);
    ydoc_map_print(doc, key, node);
}

static void
print_input_kvsets(void)
{
    int  i;
    char prefix[64];

    for (i = 0; i < tp.inp_kvset_nodec; ++i) {
        snprintf(prefix, sizeof(prefix), "in_kvset_%d", i);
        ydoc_kvset_print(&tp.doc, tp.inp_kvset_nodev[i], prefix);
    }
}

static void
print_ouput_kvset(void)
{
    ydoc_kvset_print(&tp.doc, tp.out_kvset_node, "out_kvset");
}

static void
process_yaml(void)
{
    yaml_document_t * doc = &tp.doc;
    int               root_node = 1;
    int               node, node2;
    char *            name;
    yaml_node_item_t *vec;
    int               veclen;

    name = "_meta";
    node = ydoc_map_lookup(doc, root_node, name);
    my_assert(node);
    my_assert(ydoc_node_type(doc, node) == YAML_MAPPING_NODE);

    tp.horizon = 0;
    tp.drop_tombs = 0;
    tp.pfx_len = -1;
    tp.fanout = 4;

    node2 = ydoc_map_lookup(doc, node, "horizon");
    if (node2)
        tp.horizon = ydoc_node_as_u64(doc, node2);
    node2 = ydoc_map_lookup(doc, node, "drop_tombs");
    if (node2)
        tp.drop_tombs = ydoc_node_as_bool(doc, node2);
    node2 = ydoc_map_lookup(doc, node, "pfx_len");
    if (node2)
        tp.pfx_len = ydoc_node_as_int(doc, node2);
    node2 = ydoc_map_lookup(doc, node, "fanout");
    if (node2)
        tp.fanout = ydoc_node_as_u64(doc, node2);

    name = "output_kvset";
    node = ydoc_map_lookup(doc, root_node, name);
    my_assert(node);
    my_assert(ydoc_node_type(doc, node) == YAML_SEQUENCE_NODE);

    tp.out_kvset_node = node;
    tp.out_kvset_nkeys = ydoc_seq_len(doc, node);

    name = "input_kvsets";
    node = ydoc_map_lookup(doc, root_node, name);
    my_assert(node);
    my_assert(ydoc_node_type(doc, node) == YAML_SEQUENCE_NODE);

    ydoc_node_as_seq(doc, node, &vec, &veclen);

    tp.inp_kvset_nodev = vec;
    tp.inp_kvset_nodec = veclen;
}

static void
load_yaml(struct mtf_test_info *lcl_ti)
{
    FILE *        fp;
    yaml_parser_t parser;
    int           rc, err;

    fp = fopen(tp.test_filev[tp.test_number], "rb");
    ASSERT_NE(fp, NULL);

    rc = yaml_parser_initialize(&parser);
    ASSERT_NE(rc, 0);

    yaml_parser_set_input_file(&parser, fp);

    err = !yaml_parser_load(&parser, &tp.doc);
    ASSERT_EQ(err, 0);

    yaml_parser_delete(&parser);
    fclose(fp);
}

static void
kvset_get_nth_key(
    int    kvset_node,
    int    nth,
    bool * eof_out,
    void **kdata_out,
    uint * klen_out,
    uint * nvals_out)
{
    const char *      kdata;
    int               klen;
    yaml_node_item_t *vec;
    int               veclen;

    *eof_out = !ydoc_kvset_get_nth(&tp.doc, kvset_node, nth, &kdata, &klen, &vec, &veclen);
    if (!*eof_out) {
        *kdata_out = (void *)kdata;
        *klen_out = klen;
        *nvals_out = veclen;
    }
}

static void
kvset_get_nth_val(
    int             kvset_node,
    int             nth_key,
    int             nth_value,
    bool *          eof_out,
    u64 *           seq_out,
    enum kmd_vtype *vtype_out,
    const void **   vdata_out,
    uint *          vlen_out)
{
    const char *      kdata;
    int               klen;
    yaml_node_item_t *vec;
    int               veclen;
    yaml_node_item_t *valv;
    int               valc;

    *eof_out = !ydoc_kvset_get_nth(&tp.doc, kvset_node, nth_key, &kdata, &klen, &vec, &veclen);
    /* nth_key is expected to be in range. */
    my_assert(!*eof_out);

    /* nth_value might be out of range. */
    *eof_out = (nth_value < 0 || nth_value >= veclen);
    if (*eof_out)
        return;

    /* Values are stored as a list of lists;
     *   [ [ seq, vtype, value ], [ seq, vtype, value ], ... ]
     */
    ydoc_node_as_seq(&tp.doc, vec[nth_value], &valv, &valc);
    *seq_out = ydoc_node_as_u64(&tp.doc, valv[0]);
    *vtype_out = ydoc_node_as_vtype(&tp.doc, valv[1]);

    switch (*vtype_out) {
        case vtype_val: {
            int tmp;
            *vdata_out = ydoc_node_as_str(&tp.doc, valv[2], &tmp);
            my_assert(tmp > 0);
            *vlen_out = tmp;
            if (*vlen_out < CN_SMALL_VALUE_THRESHOLD)
                *vtype_out = vtype_ival;
            break;
        }
        default:
            *vdata_out = 0;
            *vlen_out = 0;
    }
}

static void
kvset_get_nth(
    int          kvset_node,
    int          nth,
    bool *       eof,
    const void **key,
    uint *       key_len,
    void **      val,
    uint *       val_len)
{
    const char *      kdata;
    int               klen;
    const char *      vdata;
    int               vlen;
    yaml_node_item_t *vec;
    int               veclen;

    *eof = !ydoc_kvset_get_nth(&tp.doc, kvset_node, nth, &kdata, &klen, &vec, &veclen);
    if (!*eof) {

        yaml_node_item_t *valv;
        int               valc;

        ydoc_node_as_seq(&tp.doc, vec[0], &valv, &valc);
        vdata = ydoc_node_as_str(&tp.doc, valv[2], &vlen);

        *key = (void *)kdata;
        *key_len = klen;
        *val = (void *)vdata;
        *val_len = vlen;
    }
}

/*----------------------------------------------------------------
 * Handle kvset_builder_add_* functions to get key/value pairs
 * and verify them.
 */
static merr_t
_kvset_builder_add_key(struct kvset_builder *builder, const struct key_obj *kobj)
{
    void *ref_kdata;
    uint  ref_klen;
    uint  ref_nvals;
    bool  eof;
    u8    kdata[HSE_KVS_KEY_LEN_MAX];
    uint  klen;

    key_obj_copy(kdata, sizeof(kdata), &klen, kobj);

    if (tp.verbose >= VERBOSE_PER_KEY1)
        printf("add_key, expect key#%u %.*s\n", tp.next_output_key, klen, (char *)kdata);

    VERIFY_TRUE_RET(klen > 0, __LINE__);
    VERIFY_TRUE_RET(kdata != NULL, __LINE__);

    /* Get the next reference and compare */
    VERIFY_TRUE_RET(tp.next_output_key < tp.out_kvset_nkeys, __LINE__);

    eof = -1;
    kvset_get_nth_key(
        tp.out_kvset_node, tp.next_output_key, &eof, &ref_kdata, &ref_klen, &ref_nvals);
    VERIFY_TRUE_RET(!eof, __LINE__);

    /* check for same number of values */
    VERIFY_TRUE_RET(tp.next_output_val == ref_nvals, __LINE__);

    /* check for same key */
    VERIFY_TRUE_RET(klen == ref_klen, __LINE__);
    VERIFY_TRUE_RET(!memcmp(kdata, ref_kdata, klen), __LINE__);

    /* reset for next key */
    tp.next_output_key++;
    tp.next_output_val = 0;

    return 0;
}

static void
_kvset_builder_add_val_internal(
    struct kvset_builder *self,
    u64                   seq,
    enum kmd_vtype        vtype,
    const void *          vdata,
    uint                  vlen)
{
    bool           ref_eof;
    u64            ref_seq = 0;
    enum kmd_vtype ref_vtype = vtype_val;
    const void *   ref_vdata = NULL;
    uint           ref_vlen = 0;

    kvset_get_nth_val(
        tp.out_kvset_node,
        tp.next_output_key,
        tp.next_output_val,
        &ref_eof,
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
            case vtype_val:
                tag = "v";
                break;
            case vtype_cval:
                tag = "c";
                break;
            case vtype_zval:
                tag = "z";
                break;
            case vtype_ival:
                tag = "i";
                break;
            case vtype_tomb:
                tag = "t";
                break;
            case vtype_ptomb:
                tag = "pt";
                break;
        }
        printf( "%lu %s %.*s\n", (ulong)ref_seq, tag, ref_vlen,
            ref_vdata ? (char *)ref_vdata : "");
    }

    if (vtype != vtype_ptomb) {
        /* If the following checks fail, then more values have been
         * generated than were expected.
         */
        VERIFY_TRUE(!ref_eof);
        my_assert(!ref_eof);
    }

    VERIFY_EQ(seq, ref_seq);
    VERIFY_EQ(vtype, ref_vtype);
    if (vtype == vtype_val || vtype == vtype_ival) {
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
    u64                   seq,
    uint                  vbidx_kvset_node,
    uint                  vboff_nth_key,
    uint                  vlen_nth_val,
    uint                  complen)
{
    u64            tmp_seq;
    enum kmd_vtype vtype;
    const void *   vdata;
    uint           vlen;
    int            kvset_node, nth_key, nth_val;
    bool           eof;

    /* Unpack data from vref:
     *   vbidx == kvset node
     *   vboff == nth_key
     *   vblen == nth_val
     *
     * See also _kvset_iter_next_vref(), which packs this data.
     */
    kvset_node = vbidx_kvset_node;
    nth_key = vboff_nth_key;
    nth_val = vlen_nth_val;

    eof = -1;
    kvset_get_nth_val(kvset_node, nth_key, nth_val, &eof, &tmp_seq, &vtype, &vdata, &vlen);
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
    u64                     seq,
    uint                    complen)
{
    enum kmd_vtype vtype;

    if (vdata == HSE_CORE_TOMB_REG)
        vtype = vtype_tomb;
    else if (vdata == HSE_CORE_TOMB_PFX)
        vtype = vtype_ptomb;
    else if (!vdata || !vlen)
        vtype = vtype_zval;
    else if (!vdata || vlen < CN_SMALL_VALUE_THRESHOLD)
        vtype = vtype_ival;
    else
        vtype = vtype_val;

    _kvset_builder_add_val_internal(self, seq, vtype, vdata, vlen);
    return 0;
}

static merr_t
_kvset_builder_add_nonval(struct kvset_builder *self, u64 seq, enum kmd_vtype vtype)
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
    int                 kvset_node;
    u32                 src;
    u32                 cursor;
};

static merr_t
_kvset_iter_next_key(struct kv_iterator *kvi, struct key_obj *kobj, struct kvset_iter_vctx *vc)
{
    struct kv_spill_test_kvi *iter = (struct kv_spill_test_kvi *)kvi->kvi_context;

    void *vdata;
    uint  vlen;
    uint  nth_key = iter->cursor;

    kobj->ko_pfx = 0;
    kobj->ko_pfx_len = 0;
    kvset_get_nth(
        iter->kvset_node, nth_key, &kvi->kvi_eof, &kobj->ko_sfx, &kobj->ko_sfx_len, &vdata, &vlen);
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
    vc->kmd = (void *)(uintptr_t)iter->kvset_node;
    vc->nvals = 0;
    vc->off = nth_key;
    vc->next = 0;
    return 0;
}

static bool
_kvset_iter_next_vref(
    struct kv_iterator *    kvi,
    struct kvset_iter_vctx *vc,
    u64 *                   seq,
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
    int kvset_node = (int)(uintptr_t)vc->kmd;
    int nth_key = vc->off;
    int nth_val = vc->next;

    bool        eof;
    const void *lvdata;
    uint        vlen;

    eof = -1;
    kvset_get_nth_val(kvset_node, nth_key, nth_val, &eof, seq, vtype, &lvdata, &vlen);
    if (eof)
        return false;

    switch (*vtype) {
        case vtype_val:
            /* Pack data into vref:
             *   vbidx == kvset node
             *   vboff == nth_key
             *   vlen_out == nth_val
             * See also _kvset_builder_add_vref(), which unpacks this data.
             */
            *vbidx = kvset_node;
            *vboff = nth_key;
            *vlen_out = nth_val;
            break;
        case vtype_ival:
        case vtype_zval:
        case vtype_tomb:
        case vtype_ptomb:
            *vdata = (void *)lvdata;
            *vlen_out = vlen;
            break;
        case vtype_cval:
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
    int kvset_node;
    int nth_key;
    int nth_val;
    u64 seq;

    const void *vdata;
    bool        end;

    /* Need to handle vtype_val case. The rest are already provided by
     * _kvset_iter_next_vref.
     */

    if (vtype == vtype_val) {
        kvset_node = vbidx;
        nth_key = vboff;
        nth_val = *vlen_out;

        end = false;
        kvset_get_nth_val(kvset_node, nth_key, nth_val, &end, &seq, &vtype, &vdata, vlen_out);
        if (end)
            return 0;
    }

    switch (vtype) {
        case vtype_cval:
            /* not used by this test */
            assert(0);
            break;
        case vtype_val:
            *vdata_out = (void *)vdata;
            return 0;
        case vtype_ival:
            return 0;
        case vtype_zval:
            *vdata_out = 0;
            *vlen_out = 0;
            return 0;
        case vtype_tomb:
            *vdata_out = HSE_CORE_TOMB_REG;
            *vlen_out = 0;
            return 0;
        case vtype_ptomb:
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
    free(kvi->kvi_context);
}

struct kv_iterator_ops kvi_ops = {.kvi_release = kv_spill_test_kvi_release };

static merr_t
kv_spill_test_kvi_create(
    struct kv_iterator ** kvi_out,
    struct test_params *  tp,
    u32                   src,
    struct mtf_test_info *lcl_ti)
{
    struct kv_spill_test_kvi *iter =
        (struct kv_spill_test_kvi *)calloc(1, sizeof(struct kv_spill_test_kvi));
    if (!iter)
        return merr(ENOMEM);

    my_assert(src < tp->inp_kvset_nodec);

    iter->test = tp;
    iter->src = src;
    iter->kvset_node = tp->inp_kvset_nodev[src];
    iter->cursor = 0;

    iter->kvi.kvi_context = iter;
    iter->kvi.kvi_ops = &kvi_ops;

    /*
     * Caller will have a handle to the generic 'struct
     * kv_iterator' object.  It is mapped back to 'struct
     * kv_spill_test_kvi' via 'kvi->kvi_context'.
     */
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
    u64                        horizon,
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
    struct kvset_vblk_map *    vbm)
{
    memset(w, 0, sizeof(*w));

    w->cw_ds = ds;
    w->cw_tree = tree;
    w->cw_rp = rp;
    w->cw_cp = tree ? cn_tree_get_cparams(tree) : 0;
    w->cw_pfx_len = pfx_len;
    w->cw_horizon = horizon;
    w->cw_kvset_cnt = num_sources;
    w->cw_inputv = sources;
    w->cw_level = 0;
    w->cw_pc = pc;
    w->cw_cancel_request = cancel;
    w->cw_outc = num_outputs;
    w->cw_drop_tombs = drop_tombs;
    w->cw_outv = outputs;
    w->cw_output_nodev = output_nodev;
    w->cw_kvsetidv = kvsetidv;

    if (vbm)
        w->cw_vbmap = *vbm;

    return w;
}

static void
run_testcase(struct mtf_test_info *lcl_ti, int mode, const char *info)
{
    merr_t                    err;
    u32                       iterc;
    struct kv_iterator **     iterv;
    u32                       i;
    atomic_int                cancel;
    struct cn_compaction_work w;

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

    struct mpool *       ds = (struct mpool *)lcl_ti;
    u32                  shift = 0;
    struct kvset_mblocks outputs[tp.fanout];
    struct cn_tree_node *output_nodev[tp.fanout];
    uint64_t             kvsetidv[tp.fanout];
    struct kvs_rparams   rp = kvs_rparams_defaults();
    int                  pfx_len = tp.pfx_len;

    memset(outputs, 0, sizeof(outputs));
    memset(output_nodev, 0, sizeof(output_nodev));

    if (mode == MODE_SPILL) {
        struct cn_tree *tree;
        struct kvdb_health    health;

        struct kvs_cparams cp = {
            .fanout = tp.fanout, .pfx_len = tp.pfx_len,
        };

        err = cn_tree_create(&tree, "kvs", 0, &cp, &health, &rp);
        ASSERT_EQ(err, 0);
        ASSERT_NE(tree, NULL);

        cn_tree_setup(tree, NULL, NULL, &rp, NULL, 1234, 0);
        tree->ct_root->tn_childc = cp.fanout;

        for (i = 0; i < tree->ct_root->tn_childc; i++) {
            struct cn_tree_node *tn;
            char ekbuf[HSE_KVS_KEY_LEN_MAX];
            size_t eklen;

            tn = cn_node_alloc(tree, 1, i);
            ASSERT_NE(0, tn);

            eklen = snprintf(ekbuf, sizeof(ekbuf), "a.%08d", i);
            tn->tn_route_node = route_map_insert(tree->ct_route_map, tn, ekbuf, eklen);
            tn->tn_parent = tree->ct_root;
            tree->ct_root->tn_childv[i] = tn;
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
            0);

        w.cw_action = CN_ACTION_SPILL;
        w.cw_cp = &cp;

        err = cn_spill(&w);
        ASSERT_EQ(err, 0);
        cn_tree_destroy(tree);
    } else {
        /* kcompact */
        struct kvset_vblk_map vbm;
        u64 *                 blkv = mapi_safe_malloc(sizeof(*blkv) * iterc);
        u32 *                 map = mapi_safe_malloc(sizeof(*map) * iterc);

        ASSERT_TRUE(blkv != 0);
        ASSERT_TRUE(map != 0);

        memset(&vbm, 0, sizeof(vbm));
        vbm.vbm_blkv = mapi_safe_malloc(sizeof(*vbm.vbm_blkv) * iterc);

        for (i = 0; i < iterc; i++) {
            vbm.vbm_blkv[i].bk_blkid = 1000 + i;
            map[i] = 0;
        }
        vbm.vbm_map = map;
        vbm.vbm_blkc = iterc;
        vbm.vbm_mapc = iterc;
        vbm.vbm_used = 0;
        vbm.vbm_waste = 0;

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
            &vbm);

        w.cw_action = CN_ACTION_COMPACT_K;

        err = cn_kcompact(&w);
        ASSERT_EQ(err, 0);

        mapi_safe_free(vbm.vbm_blkv);
        mapi_safe_free(blkv);
        mapi_safe_free(map);
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
    load_yaml(lcl_ti);
    process_yaml();
}

static void
teardown_tcase(struct mtf_test_info *lcl_ti)
{
    yaml_document_delete(&tp.doc);
    memset(&tp.doc, 0, sizeof(tp.doc));
}

static void
run_all_tcases(struct mtf_test_info *lcl_ti)
{
    int i;

    for (i = 0; i < tp.test_filec; i++) {

        tp.test_number = i;

        if (tp.verbose >= VERBOSE_PER_FILE1)
            printf("Test File: %s\n", tp.test_filev[i]);

        setup_tcase(lcl_ti);

        if (tp.verbose >= VERBOSE_PER_FILE2)
            print_meta();
        if (tp.verbose >= VERBOSE_MAX) {
            print_input_kvsets();
            print_ouput_kvset();
        }

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
