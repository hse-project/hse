/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_perfc

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/data_tree.h>
#include <hse_util/perfc.h>
#include <hse_util/list.h>
#include <hse_util/parse_num.h>
#include <hse_util/config.h>
#include <hse_util/log2.h>
#include <hse_util/string.h>

#include <rbtree/rbtree.h>

#define PERFC_PRIO_MIN 1
#define PERFC_PRIO_MAX 4

static char *pc_type_names[] = {
    "Invalid", "Basic", "Rate", "Distribution", "Latency", "SimpleLatency",
};

/*
 * perfc_verbosity decides the highest priority level of the counters that will
 * be enabled. All counters with a priority less than or equal to
 * perfc_verbosity will be "on".
 * Later the user can change this global verbosity on the fly.
 */
u32 perfc_verbosity_default HSE_READ_MOSTLY = 2;
u32 perfc_verbosity HSE_READ_MOSTLY = 2;

struct perfc_ivl *perfc_di_ivl HSE_READ_MOSTLY;

/**
 * perfc_ctrseti_clear() - Clear a counter set instance.
 * @seti:
 */
static void
perfc_ctrseti_clear(struct perfc_seti *seti)
{
    const struct perfc_ivl *ivl;
    struct perfc_ctr_hdr   *hdr;
    struct perfc_rate      *rate;
    struct perfc_dis       *dis;
    struct perfc_val       *val;
    struct perfc_bkt       *bkt;

    u64 vadd, vsub, vtmp;
    u32 cidx;
    int i, j;

    for (cidx = 0; cidx < seti->pcs_ctrc; ++cidx) {
        hdr = &seti->pcs_ctrv[cidx].hdr;

        switch (hdr->pch_type) {
        case PERFC_TYPE_RA:
            val = hdr->pch_val;
            vadd = vsub = 0;

            for (i = 0; i < PERFC_VALPERCNT; ++i) {
                vtmp = atomic64_read(&val->pcv_vsub);
                atomic64_sub(vtmp, &val->pcv_vsub);
                vsub += vtmp;

                vtmp = atomic64_read(&val->pcv_vadd);
                atomic64_sub(vtmp, &val->pcv_vadd);
                vadd += vtmp;

                val += PERFC_VALPERCPU;
            }

            vadd = (vadd > vsub) ? (vadd - vsub) : 0;

            /* Put the current value in the old one.  This is
             * done to get a valid rate next time the counter
             * is read.
             */
            rate = &seti->pcs_ctrv[cidx].rate;
            rate->pcr_old_val = vadd;
            rate->pcr_old_time_ns = get_time_ns();
            break;

        case PERFC_TYPE_DI:
        case PERFC_TYPE_LT:
            dis = &seti->pcs_ctrv[cidx].dis;
            dis->pdi_min = 0;
            dis->pdi_max = 0;

            bkt = dis->pdi_hdr.pch_bktv;
            ivl = dis->pdi_ivl;

            for (j = 0; j < PERFC_GRP_MAX; ++j) {
                bkt = dis->pdi_hdr.pch_bktv + (PERFC_IVL_MAX + 1) * j;

                for (i = 0; i < ivl->ivl_cnt + 1; ++i, ++bkt) {
                    vtmp = atomic64_read(&bkt->pcb_vadd);
                    atomic64_sub(vtmp, &bkt->pcb_vadd);

                    vtmp = atomic64_read(&bkt->pcb_hits);
                    atomic64_sub(vtmp, &bkt->pcb_hits);
                }
            }
            break;

        case PERFC_TYPE_SL:
        case PERFC_TYPE_BA:
        default:
            val = hdr->pch_val;

            vtmp = atomic64_read(&val->pcv_vsub);
            atomic64_sub(vtmp, &val->pcv_vsub);

            vtmp = atomic64_read(&val->pcv_vadd);
            atomic64_sub(vtmp, &val->pcv_vadd);
            break;
        }
    }
}

static size_t
set_handler_ctrset(struct dt_element *dte, struct dt_set_parameters *dsp)
{
    struct perfc_seti *seti = (struct perfc_seti *)dte->dte_data;

    if (dsp->field == DT_FIELD_CLEAR)
        perfc_ctrseti_clear(seti);
    else if (dsp->field == DT_FIELD_ENABLED) {
        bool enable = (dsp->value[0] == '0') ? false : true;

        if (enable) {
            seti->pcs_handle->ps_bitmap = U64_MAX;
        } else {
            struct perfc_set *setp = seti->pcs_handle;
            int               i;

            setp->ps_bitmap = 0;
            for (i = 0; i < seti->pcs_ctrc; i++) {
                struct perfc_ctr_hdr *pch;

                pch = &seti->pcs_ctrv[i].hdr;
                if (perfc_verbosity >= pch->pch_prio)
                    setp->ps_bitmap |= (1ULL << i);
            }
        }

    } else if (dsp->field == DT_FIELD_INVALIDATE_HANDLE) {
        seti->pcs_handle = NULL;
    }

    return 1;
}

static size_t
set_handler(struct dt_element *dte, struct dt_set_parameters *dsp)
{
    return set_handler_ctrset(dte, dsp);
}

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC (1000000000ul)
#endif

static void
perfc_ra_emit(struct perfc_rate *rate, struct yaml_context *yc)
{
    char value[DT_PATH_LEN];
    struct perfc_val *val;
    u64  dt, dx, ops;
    u64  vadd, vsub;
    u64  curr, prev;
    u64  curr_ns;
    int  i;

    curr_ns = get_time_ns();
    dt = curr_ns - rate->pcr_old_time_ns;

    if (rate->pcr_old_time_ns == 0 || curr_ns < rate->pcr_old_time_ns)
        dt = 0;

    prev = rate->pcr_old_val;

    val = rate->pcr_hdr.pch_val;
    vadd = vsub = curr = 0;

    for (i = 0; i < PERFC_VALPERCNT; ++i) {
        vadd += atomic64_read(&val->pcv_vadd);
        vsub += atomic64_read(&val->pcv_vsub);
        val += PERFC_VALPERCPU;
    }

    curr = (vadd > vsub) ? (vadd - vsub) : 0;

    rate->pcr_old_time_ns = curr_ns;
    dx = curr - prev;
    rate->pcr_old_val = curr;

    ops = dt > 0 ? (dx * NSEC_PER_SEC) / dt : 0;

    u64_to_string(value, sizeof(value), dt);
    yaml_element_field(yc, "dt_ns", value);

    u64_to_string(value, sizeof(value), curr);
    yaml_element_field(yc, "curr", value);

    u64_to_string(value, sizeof(value), prev);
    yaml_element_field(yc, "prev", value);

    u64_to_string(value, sizeof(value), ops);
    yaml_element_field(yc, "rate", value);

    if (vsub > 0) {
        u64_to_string(value, sizeof(value), vadd);
        yaml_element_field(yc, "vadd", value);

        u64_to_string(value, sizeof(value), vsub);
        yaml_element_field(yc, "vsub", value);
    }
}

static void
perfc_di_emit(struct perfc_dis *dis, struct yaml_context *yc)
{
    const struct perfc_ivl *ivl = dis->pdi_ivl;

    size_t valoff, avgoff, hitoff, bktoff;
    ulong  samples, avg, sum, bound;
    char   valstr[(PERFC_IVL_MAX + 1) * 12];
    char   hitstr[(PERFC_IVL_MAX + 1) * 12];
    char   avgstr[(PERFC_IVL_MAX + 1) * 12];
    char   bktstr[(PERFC_IVL_MAX + 1) * 12];
    int    i, j;

    valstr[0] = hitstr[0] = avgstr[0] = bktstr[0] = '\000';
    valoff = avgoff = hitoff = bktoff = 0;
    samples = sum = bound = 0;

    for (i = 0; i < ivl->ivl_cnt + 1; ++i) {
        struct perfc_bkt *bkt;
        ulong             hits, val, largest;
        int               width = 3;

        bkt = dis->pdi_hdr.pch_bktv + i;
        hits = val = 0;

        for (j = 0; j < PERFC_GRP_MAX; ++j) {
            val += atomic64_read(&bkt->pcb_vadd);
            hits += atomic64_read(&bkt->pcb_hits);
            bkt += PERFC_IVL_MAX + 1;
        }

        avg = (hits > 0) ? val / hits : 0;

        largest = max_t(ulong, hits, bound);
        largest = max_t(ulong, largest, avg);

        if (largest > 9)
            width += ilog2(largest | 1000) * 77 / 256;

        u64_append(hitstr, sizeof(hitstr), hits, width, &hitoff);
        u64_append(bktstr, sizeof(bktstr), bound, width, &bktoff);
        u64_append(avgstr, sizeof(avgstr), avg, width, &avgoff);

        u64_append(valstr, sizeof(valstr), hits, -1, &valoff);
        u64_append(valstr, sizeof(valstr), bound, -1, &valoff);

        if (i < ivl->ivl_cnt)
            bound = ivl->ivl_bound[i];
        samples += hits;
        sum += val;
    }

    /* [HSE_REVISIT] perfc_parse_ctrtype() is super brittle and requires
     * that "distribution" come before any of the other key/value
     * tuples produced here.
     */
    yaml_element_field(yc, "distribution", valstr);

    u64_to_string(valstr, sizeof(valstr), dis->pdi_min);
    yaml_element_field(yc, "min", valstr);

    u64_to_string(valstr, sizeof(valstr), dis->pdi_max);
    yaml_element_field(yc, "max", valstr);

    avg = (samples > 0) ? sum / samples : 0;

    u64_to_string(valstr, sizeof(valstr), avg);
    yaml_element_field(yc, "average", valstr);

    /* 'sum' and 'hitcnt' field names must match here and for simple lat
     * counters
     */
    u64_to_string(valstr, sizeof(valstr), sum);
    yaml_element_field(yc, "sum", valstr);

    u64_to_string(valstr, sizeof(valstr), samples ?: 1);
    yaml_element_field(yc, "hitcnt", valstr);

    u64_to_string(valstr, sizeof(valstr), dis->pdi_pct * 100 / PERFC_PCT_SCALE);
    yaml_element_field(yc, "pct", valstr);

    yaml_element_field(yc, "hits", hitstr);
    yaml_element_field(yc, "avgs", avgstr);
    yaml_element_field(yc, "bkts", bktstr);
}

static void
perfc_read_hdr(struct perfc_ctr_hdr *hdr, u64 *vadd, u64 *vsub)
{
    struct perfc_val *val = hdr->pch_val;
    int i;

    *vadd = *vsub = 0;

    /* Must skip by values-per-cpu due to how multiple per-cpu values
     * from different counters are packed into cache lines.  E.g.,
     * summing over val[i].pcv_vadd would go horribly awry...
     */
    for (i = 0; i < PERFC_VALPERCNT; ++i) {
        *vadd += atomic64_read(&val->pcv_vadd);
        *vsub += atomic64_read(&val->pcv_vsub);
        val += PERFC_VALPERCPU;
    }
}

void
perfc_read(struct perfc_set *pcs, const u32 cidx, u64 *vadd, u64 *vsub)
{
    struct perfc_seti *pcsi;

    pcsi = perfc_ison(pcs, cidx);
    if (pcsi)
        perfc_read_hdr(&pcsi->pcs_ctrv[cidx].hdr, vadd, vsub);
}

static size_t
emit_handler_ctrset(struct dt_element *dte, struct yaml_context *yc)
{
    struct perfc_seti *   seti = dte->dte_data;
    char                  value[DT_PATH_LEN];
    struct perfc_ctr_hdr *ctr_hdr;
    u32                   cidx;

    yaml_start_element(yc, "path", dte->dte_path);
    yaml_element_field(yc, "name", seti->pcs_ctrseti_name);

    if (seti->pcs_handle) {
        u64_to_string(value, sizeof(value), seti->pcs_handle->ps_bitmap == U64_MAX);
        yaml_element_field(yc, "enabled", value);
    } else {
        yaml_element_field(yc, "enabled", "0");
    }

    yaml_start_element_type(yc, "counters");

    /*
     * Emit all the counters of the counter set instance.
     */
    for (cidx = 0; cidx < seti->pcs_ctrc; cidx++) {
        u64 vadd, vsub;

        ctr_hdr = &seti->pcs_ctrv[cidx].hdr;

        yaml_start_element(yc, "name", seti->pcs_ctrnamev[cidx].pcn_name);

        yaml_element_field(yc, "header", seti->pcs_ctrnamev[cidx].pcn_hdr);

        yaml_element_field(yc, "description", seti->pcs_ctrnamev[cidx].pcn_desc);

        yaml_element_field(yc, "type", pc_type_names[ctr_hdr->pch_type]);

        u64_to_string(value, sizeof(value), ctr_hdr->pch_prio);
        yaml_element_field(yc, "priority", value);

        u64_to_string(value, sizeof(value), (seti->pcs_handle->ps_bitmap & (1ul << cidx)) >> cidx);
        yaml_element_field(yc, "is_on", value);

        switch (ctr_hdr->pch_type) {
        case PERFC_TYPE_BA:
            perfc_read_hdr(ctr_hdr, &vadd, &vsub);
            vadd = vadd > vsub ? vadd - vsub : 0;

            u64_to_string(value, sizeof(value), vadd);
            yaml_element_field(yc, "value", value);
            break;

        case PERFC_TYPE_RA:
            perfc_ra_emit(&seti->pcs_ctrv[cidx].rate, yc);
            break;

        case PERFC_TYPE_SL:
            perfc_read_hdr(ctr_hdr, &vadd, &vsub);

            /* 'sum' and 'hitcnt' field names must match here and
             * for distribution counters
             */
            u64_to_string(value, sizeof(value), vadd);
            yaml_element_field(yc, "sum", value);

            u64_to_string(value, sizeof(value), vsub);
            yaml_element_field(yc, "hitcnt", value);
            break;

        case PERFC_TYPE_DI:
        case PERFC_TYPE_LT:
            perfc_di_emit(&seti->pcs_ctrv[cidx].dis, yc);
            break;

        default:
            break;
        }

        yaml_end_element(yc);
    }

    yaml_end_element_type(yc);
    yaml_end_element(yc);

    return 1;
}

/**
 * emit_handler() - the output fits into a YAML document. spacing is driven by
 * YAML context.
 * @dte:
 * @yc:
 *
 * A performance (with its preceding data and perfc elements
 * looks like this:
 * data:
 *   - perfc:
 *     - path: /data/perfc/mpool/mpool_01223/open_count
 *       count: 17
 *
 * Fields are indented 6 spaces.
 */
static size_t
emit_handler(struct dt_element *dte, struct yaml_context *yc)
{
    return emit_handler_ctrset(dte, yc);
}

static size_t
count_handler(struct dt_element *element)
{
    return 1;
}

/**
 * remove_handler_ctrset()
 * @dte:
 *
 * Handle called by the tree to free a counter set instance.
 */
static size_t
remove_handler_ctrset(struct dt_element *dte)
{
    free_aligned(dte->dte_data);
    free(dte);

    return 0;
}

static size_t
remove_handler(struct dt_element *dte)
{
    return remove_handler_ctrset(dte);
}

struct dt_element_ops perfc_ops = {
    .emit = emit_handler,
    .set = set_handler,
    .count = count_handler,
    .remove = remove_handler,
};

static size_t
root_set_handler(struct dt_element *dte, struct dt_set_parameters *dsp)
{
    return 1;
}

static size_t
root_emit_handler(struct dt_element *me, struct yaml_context *yc)
{
    yaml_start_element_type(yc, "perfc");

    return 1;
}

static size_t
root_remove_handler(struct dt_element *element)
{
    /* Whole of dt must have been removed...*/
    return 0;
}

static struct dt_element_ops perfc_root_ops = {
    .set = root_set_handler,
    .emit = root_emit_handler,
    .remove = root_remove_handler,
};

static size_t
perfc_verbosity_set_handler(struct dt_element *dte, struct dt_set_parameters *dsp)
{
    /* walk through the perfc subtree and refresh bitmaps depending upon
     * the current value of perfc_verbosity
     */
    u32                val, old;
    struct hse_config *mc = (struct hse_config *)dte->dte_data;
    merr_t             err;
    struct rb_node *   node;
    const char *       path = "/data/perfc";
    const size_t       pathlen = strlen(path);

    old = *(u32 *)mc->data;
    err = parse_u32(dsp->value, &val);
    if (err)
        return 0;

    memcpy(mc->data, &val, sizeof(val));
    if (old == val)
        return 1; /* nothing changed */

    /* update bitmaps for all counter sets */
    dte = dt_find_locked(dt_data_tree, path, 0);
    while (dte) {
        struct perfc_seti *seti;
        struct perfc_set * setp;
        int                i;

        if (dte->dte_data) {
            seti = dte->dte_data;
            setp = seti->pcs_handle;

            setp->ps_bitmap = 0;
            for (i = 0; i < seti->pcs_ctrc; i++) {
                struct perfc_ctr_hdr *pch;

                pch = &seti->pcs_ctrv[i].hdr;
                if (perfc_verbosity >= pch->pch_prio)
                    setp->ps_bitmap |= (1ULL << i);
            }
        }

        node = rb_next(&dte->dte_node);
        dte = container_of(node, struct dt_element, dte_node);
        if (dte && strncmp(path, dte->dte_path, pathlen))
            /* We've hit the first thing that doesn't include
             * the search path. That means we're done. */
            break;
    }

    return 1;
}

merr_t
perfc_init(void)
{
    static struct dt_element dte = {
        .dte_data = NULL,
        .dte_ops = &perfc_root_ops,
        .dte_type = DT_TYPE_ROOT,
        .dte_path = PERFC_ROOT_PATH,
    };
    u64    boundv[PERFC_IVL_MAX];
    u64    bound;
    merr_t err;
    int    i;

    /* Create the bounds vector for the default latency distribution
     * histogram.  The first ten bounds run from 100ns to 1us with a
     * 100ns step.  The remaining bounds run from 1us on up initially
     * with a power-of-two step, and then with a power-of-four step,
     * rounding each bound down to a number that is readable (i.e.,
     * having only one or two significant digits).
     */
    assert(NELEM(boundv) > 9);
    bound = 100;
    for (i = 0; i < PERFC_IVL_MAX; ++i) {
        ulong b;
        ulong mult;

        /* The first ten bounds run from 100ns to 1us with a 100ns
         * step...
         */
        if (i < 9) {
            boundv[i] = bound * (i + 1);
            continue;
        }

        /* ... and the remaining bounds run from 1us on up initially
         * with a power-of-two step, and then with a power-of-four step,
         * rounding each bound down to a number that is readable (i.e.,
         * having only one or two significant digits).
         */
        if (bound == 100)
            bound = 1000;

        mult = 1;
        b = bound;
        while (b > 30) {
            b /= 10;
            mult *= 10;
        }

        boundv[i] = b * mult;
        bound *= i < 23 ? 2 : 4;
    }

    err = perfc_ivl_create(PERFC_IVL_MAX, boundv, &perfc_di_ivl);
    if (ev(err))
        return err;

    dt_add(dt_data_tree, &dte);

    CFG("perfc",
        "perfc_verbosity",
        &perfc_verbosity,
        sizeof(perfc_verbosity),
        &perfc_verbosity_default,
        NULL,
        NULL,
        NULL,
        perfc_verbosity_set_handler,
        show_u32,
        true);

    return 0;
}

void
perfc_shutdown(void)
{
    if (!dt_data_tree)
        return;

    dt_remove_recursive(dt_data_tree, PERFC_ROOT_PATH);

    perfc_ivl_destroy(perfc_di_ivl);
    perfc_di_ivl = NULL;
}

merr_t
perfc_ivl_create(int boundc, const u64 *boundv, struct perfc_ivl **ivlp)
{
    struct perfc_ivl *ivl;
    size_t            sz;
    int               i, j;

    *ivlp = NULL;

    if (ev(boundc < 1 || boundc > PERFC_IVL_MAX))
        return merr(EINVAL);

    sz = sizeof(*ivl);
    sz += sizeof(ivl->ivl_bound[0]) * boundc;

    ivl = alloc_aligned(sz, SMP_CACHE_BYTES);
    if (ev(!ivl))
        return merr(ENOMEM);

    memset(ivl, 0, sz);
    ivl->ivl_cnt = boundc;
    memcpy(ivl->ivl_bound, boundv, sizeof(*boundv) * boundc);

    i = j = 0;
    while (i < NELEM(ivl->ivl_map) && j < ivl->ivl_cnt) {
        ivl->ivl_map[i] = j;

        if ((1ul << i) < ivl->ivl_bound[j])
            ++i;
        else
            ++j;
    }

    if (j >= ivl->ivl_cnt)
        --j;

    while (i < NELEM(ivl->ivl_map))
        ivl->ivl_map[i++] = j;

    *ivlp = ivl;

    return 0;
}

void
perfc_ivl_destroy(const struct perfc_ivl *ivl)
{
    free_aligned(ivl);
}

static enum perfc_type
perfc_ctr_name2type(const char *ctr_name)
{
    const char *type_name;
    char *      fam_name;

    if (ev(strncmp(ctr_name, PERFC_CTR_IDX_PREFIX, strlen(PERFC_CTR_IDX_PREFIX)) != 0))
        return PERFC_TYPE_INVAL;
    type_name = ctr_name + strlen(PERFC_CTR_IDX_PREFIX);

    /* After PERFC_EN_ we should have 2 letters for the counter
     * type name before the next '_' and then the family name.
     */
    fam_name = strchr(type_name, '_');
    if (ev((fam_name == NULL) || (type_name == fam_name) ||
           (fam_name - type_name != PERCF_CTR_TYPE_LEN)))
        return PERFC_TYPE_INVAL;

    if (!strncmp(type_name, PERFC_CTR_TYPE_BA, PERCF_CTR_TYPE_LEN))
        return PERFC_TYPE_BA;
    else if (!strncmp(type_name, PERFC_CTR_TYPE_RA, PERCF_CTR_TYPE_LEN))
        return PERFC_TYPE_RA;
    else if (!strncmp(type_name, PERFC_CTR_TYPE_DI, PERCF_CTR_TYPE_LEN))
        return PERFC_TYPE_DI;
    else if (!strncmp(type_name, PERFC_CTR_TYPE_LT, PERCF_CTR_TYPE_LEN))
        return PERFC_TYPE_LT;
    else if (!strncmp(type_name, PERFC_CTR_TYPE_SL, PERCF_CTR_TYPE_LEN))
        return PERFC_TYPE_SL;

    return ev(PERFC_TYPE_INVAL);
}

merr_t
perfc_ctrseti_alloc(
    const char *             component,
    const char *             name,
    const struct perfc_name *ctrv,
    u32                      ctrc,
    const char *             ctrseti_name,
    struct perfc_set *       setp)
{
    struct perfc_seti *seti;
    struct dt_element *dte;
    char               path[DT_PATH_LEN];
    char               family[DT_PATH_LEN] = "";
    u32                err = 0;
    const char *       famptr;
    size_t             valdatasz, sz;
    void              *valdata, *valcur;
    char *             meaning;
    u32                famlen;
    u32                type;
    u32                n, i;

    assert(setp);

    setp->ps_seti = NULL;
    setp->ps_bitmap = 0;

    if (ev(ctrc == 0))
        return merr(EINVAL);

    /*
     * Find out the number of counters in the set.
     * And check the counter names syntax.
     *
     * The counter name syntax is:
     *
     * PERFC_<counter type>_<family name>_<meaning>
     * <counter type> is one of "BA", "RA", "DI"
     * <family name> is all caps and doesn't contain '_'
     * <meaning> describes the meaning of the counter. It can contain
     * '_' character.
     *
     */
    for (i = 0; i < ctrc; i++) {
        const char *name = ctrv[i].pcn_name;

        if (ev(perfc_ctr_name2type(name) == PERFC_TYPE_INVAL))
            return merr(EINVAL);

        /* family name is after PERFC_XX_ */
        famptr = name + strlen(PERFC_CTR_IDX_END);

        /*
         * Should be a "-" after the family name and the family
         * name should be at least one character.
         */
        meaning = strchr(famptr, '_');
        if (ev(meaning == NULL || meaning == famptr))
            return merr(EINVAL);

        famlen = meaning - famptr;

        /* It should be the counter meaning after <family name>_ */
        meaning++;
        if (ev(strlen(meaning) == 0))
            return merr(EINVAL);

        if (strlen(family) == 0) {
            strncpy(family, famptr, famlen);
            family[famlen] = 0;
        } else {
            /* Check that the family name is the same for all
             * the set counters
             */
            if (ev(strncmp(family, famptr, strlen(family))))
                return merr(EINVAL);
        }
    }

    sz = snprintf(
        path, sizeof(path), PERFC_ROOT_PATH "/%s/%s/%s/%s", component, name, family, ctrseti_name);
    if (ev(sz >= sizeof(path)))
        return merr(EINVAL);

    dte = dt_find(dt_data_tree, path, 1 /*exact*/);
    if (dte) {
        seti = (struct perfc_seti *)dte->dte_data;

        /* [HSE_REVISIT] Fix me: mp_test.c abuses this... */
        ev(seti->pcs_handle != NULL);

        seti->pcs_handle = setp;
        setp->ps_seti = seti;
        return 0;
    }

    /* Cannot use the static allocation trick that Error Counters use
     * because we want to support per-instance Performance Counters
     * and the static trick would result in the same space being used
     * for each instance.
     */
    dte = calloc(1, sizeof(*dte));
    if (ev(!dte))
        return merr(ENOMEM);

    dte->dte_type = DT_TYPE_PERFC;
    dte->dte_ops = &perfc_ops;
    strlcpy(dte->dte_path, path, sizeof(dte->dte_path));

    /* Allocate the counter set instance in one big chunk.
     */
    sz = sizeof(*seti) + sizeof(seti->pcs_ctrv[0]) * ctrc;
    sz = roundup(sz, SMP_CACHE_BYTES * 2);

    for (n = i = 0; i < ctrc; ++i) {
        const struct perfc_name *entry = &ctrv[i];

        type = perfc_ctr_name2type(entry->pcn_name);

        if (!(type == PERFC_TYPE_DI || type == PERFC_TYPE_LT))
            ++n;
    }

    n = ctrc - n + (roundup(n, 4) / 4) + 1;

    valdatasz = sizeof(struct perfc_val) * PERFC_VALPERCNT * PERFC_VALPERCPU * n + 1;

    seti = alloc_aligned(sz + valdatasz, SMP_CACHE_BYTES * 2);
    if (ev(!seti)) {
        free(dte);
        return merr(ENOMEM);
    }

    memset(seti, 0, sz + valdatasz);
    strlcpy(seti->pcs_path, path, sizeof(seti->pcs_path));
    strlcpy(seti->pcs_famname, family, sizeof(seti->pcs_famname));
    strlcpy(seti->pcs_ctrseti_name, ctrseti_name, sizeof(seti->pcs_ctrseti_name));
    seti->pcs_handle = setp;
    seti->pcs_ctrnamev = ctrv;
    seti->pcs_ctrc = ctrc;

    valdata = (char *)seti + sz;
    valcur = NULL;
    n = 0;

    /* For each counter in the set, initialize the counter according
     * to the counter type.
     */
    for (i = 0; i < ctrc; i++) {
        const struct perfc_name *entry = &ctrv[i];
        struct perfc_ctr_hdr *   pch;
        const struct perfc_ivl * ivl;

        ivl = entry->pcn_ivl ?: perfc_di_ivl;
        type = perfc_ctr_name2type(entry->pcn_name);

        pch = &seti->pcs_ctrv[i].hdr;
        pch->pch_type = type;
        pch->pch_flags = entry->pcn_flags;
        pch->pch_prio = entry->pcn_prio;
        clamp_t(typeof(pch->pch_prio), pch->pch_prio, PERFC_PRIO_MIN, PERFC_PRIO_MAX);

        if (perfc_verbosity >= pch->pch_prio)
            setp->ps_bitmap |= (1ULL << i);

        if (type == PERFC_TYPE_DI || type == PERFC_TYPE_LT) {
            struct perfc_dis *dis = &seti->pcs_ctrv[i].dis;

            if (ev(ivl->ivl_cnt > PERFC_IVL_MAX)) {
                err = merr(EINVAL);
                break;
            }

            dis->pdi_pct = entry->pcn_samplepct * PERFC_PCT_SCALE / 100;
            dis->pdi_ivl = ivl;

            pch->pch_bktv = valdata;
            valdata += sizeof(struct perfc_val) * PERFC_VALPERCNT * PERFC_VALPERCPU;
        } else {
            if (!valcur || (n % PERFC_VALPERCPU) == 0) {
                valcur = valdata;
                valdata += sizeof(struct perfc_val) * PERFC_VALPERCNT * PERFC_VALPERCPU;
            }

            pch->pch_val = valcur;
            valcur += sizeof(struct perfc_val);
            ++n;
        }
    }

    if (ev(err)) {
        free_aligned(seti);
        free(dte);
        return err;
    }

    dte->dte_data = seti;
    dt_add(dt_data_tree, dte);

    setp->ps_seti = seti;

    return 0;
}

void
perfc_ctrseti_free(struct perfc_set *set)
{
    struct perfc_seti *seti;

    if (!dt_data_tree)
        return;

    assert(set);

    seti = set->ps_seti;
    if (!seti)
        return;

    /* The remove handler will free anything hanging from the counter set */
    dt_remove_by_name(dt_data_tree, seti->pcs_path);
    set->ps_seti = NULL;
}

/**
 * perfc_ctrseti_path() - get the counter set path
 * @set:
 */
char *
perfc_ctrseti_path(struct perfc_set *set)
{
    struct perfc_seti *seti = set->ps_seti;

    return seti ? seti->pcs_path : NULL;
}

void
perfc_ctrseti_invalidate_handle(struct perfc_set *set)
{
    struct dt_set_parameters    dsp;
    union dt_iterate_parameters dip = {.dsp = &dsp };
    struct perfc_seti *         seti = set->ps_seti;
    char                        path[DT_PATH_LEN];

    if (seti == NULL)
        return;

    strlcpy(path, perfc_ctrseti_path(set), sizeof(path));
    dsp.path = path;
    dsp.value = NULL;
    dsp.value_len = 0;
    dsp.field = DT_FIELD_INVALIDATE_HANDLE;

    dt_iterate_cmd(dt_data_tree, DT_OP_SET, dsp.path, &dip, 0, 0, 0);
}

_Static_assert(sizeof(struct perfc_val) >= sizeof(struct perfc_bkt), "sizeof perfc_bkt too large");

static HSE_ALWAYS_INLINE void
perfc_latdis_record(struct perfc_dis *dis, u64 sample)
{
    struct perfc_bkt *bkt;
    u32               i;

    if (sample > dis->pdi_max)
        dis->pdi_max = sample;
    else if ((sample < dis->pdi_min) || (dis->pdi_min == 0))
        dis->pdi_min = sample;

    bkt = dis->pdi_hdr.pch_bktv;
    bkt += (raw_smp_processor_id() % PERFC_GRP_MAX) * (PERFC_IVL_MAX + 1);

    /* Index into ivl_map[] with ilog2(sample) to skip buckets whose bounds
     * are smaller than sample.  Note that we constrain sample to produce an
     * index within the size of the map.
     */
    if (sample > 0) {
        const struct perfc_ivl *ivl = dis->pdi_ivl;

        i = ivl->ivl_map[ilog2(sample & 0x7ffffffffffffffful)];

        while (i < ivl->ivl_cnt && sample >= ivl->ivl_bound[i])
            ++i;

        bkt += i;
    }

    atomic64_add(sample, &bkt->pcb_vadd);
    atomic64_add(1, &bkt->pcb_hits);
}

void
perfc_lat_record_impl(struct perfc_dis *dis, u64 sample)
{
    assert(dis->pdi_hdr.pch_type == PERFC_TYPE_LT);

    if (sample % PERFC_PCT_SCALE < dis->pdi_pct)
        perfc_latdis_record(dis, cycles_to_nsecs(get_cycles() - sample));
}

void
perfc_dis_record_impl(struct perfc_dis *dis, u64 sample)
{
    assert(dis->pdi_hdr.pch_type == PERFC_TYPE_DI);

    if (get_cycles() % PERFC_PCT_SCALE < dis->pdi_pct)
        perfc_latdis_record(dis, sample);
}

#if HSE_MOCKING
#include "perfc_ut_impl.i"
#endif /* HSE_MOCKING */
