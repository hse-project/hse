/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_perfc

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/data_tree.h>
#include <hse_util/minmax.h>
#include <hse_util/parse_num.h>
#include <hse_util/log2.h>
#include <hse_util/string.h>
#include <hse_util/event_counter.h>
#include <hse_util/xrand.h>
#include <hse_util/perfc.h>

static const char * const perfc_ctr_type2name[] = {
    "Invalid", "Basic", "Rate", "Latency", "Distribution", "SimpleLatency",
};

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
perfc_set_handler_ctrset(struct dt_element *dte, struct dt_set_parameters *dsp)
{
    struct perfc_seti *seti = dte->dte_data;
    size_t nchanged = 0;

    if (dsp->field == DT_FIELD_CLEAR) {
        perfc_ctrseti_clear(seti);
        return seti->pcs_ctrc;
    }

    if (dsp->field == DT_FIELD_ENABLED) {
        struct perfc_set *setp = seti->pcs_handle;
        char *endptr = NULL;
        ulong prio;

        errno = 0;
        prio = strtoul(dsp->value, &endptr, 0);

        if (ev_err(prio == ULONG_MAX && errno))
            return 0;

        if (ev_err(endptr == dsp->value))
            return 0;

        if (endptr && !endptr[0])
            endptr = NULL;

        /* Caller can supply a list of counter or family names in addition to the
         * priority. For example:
         *
         *   curl -X PUT ... data/perfc?enabled=3:PERFC_BA_C0SKING_QLEN:KVDBOP
         */
        for (uint cidx = 0; cidx < seti->pcs_ctrc; ++cidx) {
            const struct perfc_ctr_hdr *pch = &seti->pcs_ctrv[cidx].hdr;
            uint64_t mask = 1ul << cidx;

            if (endptr) {
                if (!strstr(endptr, seti->pcs_ctrnamev[cidx].pcn_name) &&
                    !strstr(endptr, seti->pcs_famname)) {
                    continue;
                }
            }

            if (prio >= pch->pch_prio) {
                nchanged += !(setp->ps_bitmap & mask);
                setp->ps_bitmap |= mask;
            } else {
                nchanged += !!(setp->ps_bitmap & mask);
                setp->ps_bitmap &= ~mask;
            }
        }
    }

    return nchanged;
}

static size_t
perfc_set_handler(struct dt_element *dte, struct dt_set_parameters *dsp)
{
    return perfc_set_handler_ctrset(dte, dsp);
}

static void
perfc_ra_emit(struct perfc_rate *rate, struct yaml_context *yc)
{
    char value[DT_PATH_MAX];
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
perfc_emit_handler_ctrset(struct dt_element *dte, struct yaml_context *yc)
{
    struct perfc_seti *   seti = dte->dte_data;
    char                  value[DT_PATH_MAX];
    struct perfc_ctr_hdr *ctr_hdr;
    u32                   cidx;

    yaml_start_element(yc, "path", dte->dte_path);
    yaml_element_field(yc, "name", seti->pcs_ctrseti_name);

    if (seti->pcs_handle) {
        yaml_field_fmt(yc, "enabled", "0x%lx", seti->pcs_handle->ps_bitmap);
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
        yaml_element_field(yc, "type", perfc_ctr_type2name[ctr_hdr->pch_type]);

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
 * perfc_emit_handler() - the output fits into a YAML document. spacing is driven by
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
perfc_emit_handler(struct dt_element *dte, struct yaml_context *yc)
{
    return perfc_emit_handler_ctrset(dte, yc);
}

/**
 * perfc_remove_handler_ctrset()
 * @dte:
 *
 * Handle called by the tree to free a counter set instance.
 */
static size_t
perfc_remove_handler_ctrset(struct dt_element *dte)
{
    free_aligned(dte->dte_data);
    free(dte);

    return 0;
}

static size_t
perfc_remove_handler(struct dt_element *dte)
{
    return perfc_remove_handler_ctrset(dte);
}

struct dt_element_ops perfc_ops = {
    .dto_emit = perfc_emit_handler,
    .dto_set = perfc_set_handler,
    .dto_remove = perfc_remove_handler,
};

static size_t
perfc_root_emit_handler(struct dt_element *dte, struct yaml_context *yc)
{
    yaml_start_element_type(yc, basename(dte->dte_path));

    return 1;
}

static struct dt_element_ops perfc_root_ops = {
    .dto_emit = perfc_root_emit_handler,
};

merr_t
perfc_init(void)
{
    static struct dt_element hse_dte_perfc = {
        .dte_ops = &perfc_root_ops,
        .dte_type = DT_TYPE_ROOT,
        .dte_file = __FILE__,
        .dte_line = __LINE__,
        .dte_func = __func__,
        .dte_path = DT_PATH_PERFC,
    };
    u64    boundv[PERFC_IVL_MAX];
    u64    bound;
    merr_t err;
    int    rc, i;

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

    rc = dt_add(&hse_dte_perfc);
    if (ev(rc)) {
        perfc_ivl_destroy(perfc_di_ivl);
        perfc_di_ivl = NULL;
        return merr(rc);
    }

    return 0;
}

void
perfc_fini(void)
{
    dt_remove_recursive(DT_PATH_PERFC);

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
perfc_ctr_name2type(const char *ctrname, char *type, char *family, char *mean)
{
    static const char list[] = "BA,RA,LT,DI,SL"; /* must be in perfc_type order */
    const char *pc;
    int n;

    n = sscanf(ctrname, "PERFC_%[A-Z]_%[A-Z0-9]_%[_A-Z0-9]", type, family, mean);

    if (n == 3 && type[1]) {
        pc = strstr(list, type);
        if (pc)
            return ((pc - list) / 3) + 1;
    }

    return PERFC_TYPE_INVAL;
}

merr_t
perfc_ctrseti_alloc(
    uint                     prio,
    const char              *group,
    const struct perfc_name *ctrv,
    size_t                   ctrc,
    const char              *ctrseti_name,
    const char              *file,
    int                      line,
    struct perfc_set *       setp)
{
    enum perfc_type typev[PERFC_CTRS_MAX];
    char family[DT_PATH_ELEMENT_MAX];
    struct perfc_seti *seti = NULL;
    struct dt_element *dte = NULL;
    char path[DT_PATH_MAX];
    void *valdata, *valcur;
    size_t valdatasz, sz;
    size_t familylen;
    merr_t err = 0;
    u32 n, i;
    int rc;

    if (!group || !ctrv || ctrc < 1 || ctrc > PERFC_CTRS_MAX || !setp)
        return merr(EINVAL);

    setp->ps_seti = NULL;
    setp->ps_bitmap = 0;

    if (!ctrseti_name)
        ctrseti_name = "set";

    family[0] = '\000';
    familylen = 0;

    /*
     * Verify all the counter names in the set and determine their types.
     *
     * The counter name syntax is:
     *
     * PERFC_<type>_<family>_<meaning>
     *
     * <type>     one of "BA", "RA", "LT", "DI", "SI"
     * <family>   [A-Z0-9]+
     * <meaning>  [_A-Z0-9]+
     *
     * where all counters in a set must have the same <family>, and then
     * <meaning> distinguishes different counters of the same type (so
     * hierarchically speaking <family> should come before <type> ...)
     */
    for (i = 0; i < ctrc; i++) {
        const char *ctrname = ctrv[i].pcn_name;
        char typebuf[64], fambuf[64], meanbuf[64];

        if (strlen(ctrname) >= sizeof(typebuf)) {
            err = merr(ENAMETOOLONG);
            goto errout;
        }

        typev[i] = perfc_ctr_name2type(ctrname, typebuf, fambuf, meanbuf);

        if (typev[i] == PERFC_TYPE_INVAL) {
            err = merr(EINVAL);
            goto errout;
        }

        if (familylen == 0) {
            familylen = strlcpy(family, fambuf, sizeof(family));
            continue;
        }

        /* Check that the family name is the same for all
         * the set counters
         */
        if (strcmp(family, fambuf)) {
            err = merr(EINVAL);
            goto errout;
        }
    }

    assert(familylen > 0);

    sz = snprintf(path, sizeof(path), "%s/%s/%s/%s",
                  DT_PATH_PERFC, group, family, ctrseti_name);
    if (sz >= sizeof(path)) {
        err = merr(EINVAL);
        goto errout;
    }

    dte = dt_find(path, 1 /*exact*/);
    if (dte) {
        seti = (struct perfc_seti *)dte->dte_data;

        /* [HSE_REVISIT] Fix me: mp_test.c abuses this... */
        ev(seti->pcs_handle != NULL);

        seti->pcs_handle = setp;
        setp->ps_seti = seti;
        return 0;
    }

    dte = aligned_alloc(alignof(*dte), sizeof(*dte));
    if (ev(!dte)) {
        err = merr(ENOMEM);
        goto errout;
    }

    memset(dte, 0, sizeof(*dte));
    dte->dte_type = DT_TYPE_PERFC;
    dte->dte_ops = &perfc_ops;
    strlcpy(dte->dte_path, path, sizeof(dte->dte_path));

    /* Allocate the counter set instance in one big chunk.
     */
    sz = sizeof(*seti) + sizeof(seti->pcs_ctrv[0]) * ctrc;
    sz = roundup(sz, SMP_CACHE_BYTES * 2);

    for (n = i = 0; i < ctrc; ++i) {
        enum perfc_type type = typev[i];

        if (!(type == PERFC_TYPE_DI || type == PERFC_TYPE_LT))
            ++n;
    }

    n = ctrc - n + (roundup(n, 4) / 4) + 1;

    valdatasz = sizeof(struct perfc_val) * PERFC_VALPERCNT * PERFC_VALPERCPU * n + 1;

    seti = alloc_aligned(sz + valdatasz, SMP_CACHE_BYTES * 2);
    if (!seti) {
        err = merr(ENOMEM);
        goto errout;
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
        enum perfc_type type;

        ivl = entry->pcn_ivl ?: perfc_di_ivl;
        type = typev[i];

        pch = &seti->pcs_ctrv[i].hdr;
        pch->pch_type = type;
        pch->pch_flags = entry->pcn_flags;
        pch->pch_prio = entry->pcn_prio;
        clamp_t(typeof(pch->pch_prio), pch->pch_prio, PERFC_LEVEL_MIN, PERFC_LEVEL_MAX);

        if (prio >= pch->pch_prio)
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

    if (!err) {
        dte->dte_data = seti;
        setp->ps_seti = seti;

        rc = dt_add(dte);
        if (ev(rc))
            err = merr(rc);
    }

  errout:
    if (err) {
        log_warnx("unable to alloc perf counter %s/%s/%s from %s:%d: @@e",
                  err, group, family, ctrseti_name, file, line);
        setp->ps_bitmap = 0;
        setp->ps_seti = NULL;
        free_aligned(seti);
        free(dte);
    }

    return err;
}

void
perfc_ctrseti_free(struct perfc_set *set)
{
    struct perfc_seti *seti;

    assert(set);

    seti = set->ps_seti;
    if (!seti)
        return;

    /* The remove handler will free anything hanging from the counter set */
    dt_remove_by_name(seti->pcs_path);
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

static_assert(sizeof(struct perfc_val) >= sizeof(struct perfc_bkt), "sizeof perfc_bkt too large");

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
    bkt += (hse_getcpu(NULL) % PERFC_GRP_MAX) * (PERFC_IVL_MAX + 1);

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

    if (xrand64_tls() % PERFC_PCT_SCALE < dis->pdi_pct)
        perfc_latdis_record(dis, sample);
}

#if HSE_MOCKING
#include "perfc_ut_impl.i"
#endif /* HSE_MOCKING */
