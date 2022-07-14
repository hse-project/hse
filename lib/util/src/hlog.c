/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

/*
 * References
 * ----------
 *
 * 1. Stefan Heule, Marc Nunkesser, and Alexander Hall.  HyperLogLog in
 *    Practice: Algorithmic Engineering of a State of The Art Cardinality
 *    Estimation Algorithm.
 *
 *    https://research.google.com/pubs/pub40671.html
 *
 * 2. Appendix to HyperLogLog in Practice: Algorithmic Engineering of a State
 *    of the Art Cardinality Estimation Algorithm
 *
 *    http://goo.gl/iU8Ig
 *
 * 3. P. Flajolet, Eric Fusy, O. Gandouet, and F. Meunier.  Hyperloglog: The
 *    analysis of a near-optimal cardinality estimation algorithm. In Analysis
 *    of Algorithms (AOFA), pages 127-146, 2007.
 *
 *    http://algo.inria.fr/flajolet/Publications/FlFuGaMe07.pdf
 */

#define MTF_MOCK_IMPL_hlog

#include <hse_util/platform.h>
#include <error/merr.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_util/event_counter.h>

#include <hse_util/hlog.h>

#include <hyperloglog_tables.h>

#include <math.h>

struct hlog {
    uint64_t nkeys;
    uint64_t  mask;
    uint precision;
    uint regc;
    uint8_t * regv;
};

#define HLOG_PRECISION_MIN 4
#define HLOG_PRECISION_MAX 18

merr_t
hlog_create(struct hlog **hlog_out, uint p)
{
    struct hlog *hlog;
    uint         regc, sz;

    if (p < HLOG_PRECISION_MIN || p > HLOG_PRECISION_MAX)
        return merr(ev(EINVAL));

    regc = hlog_size(p);

    hlog = calloc(1, sizeof(*hlog));
    if (!hlog)
        return merr(ev(ENOMEM));

    sz = regc * sizeof(*hlog->regv);
    sz = ALIGN(sz, PAGE_SIZE);

    hlog->regv = alloc_page_aligned(sz);
    if (ev(!hlog->regv)) {
        free(hlog);
        return merr(ENOMEM);
    }

    memset(hlog->regv, 0, sz);

    hlog->precision = p;
    hlog->regc = regc;
    hlog->mask = (((u64)1) << p) - 1;

    *hlog_out = hlog;
    return 0;
}

void
hlog_destroy(struct hlog *hlog)
{
    if (!hlog)
        return;

    free_aligned(hlog->regv);
    free(hlog);
}

void
hlog_reset(struct hlog *hlog)
{
    if (ev(!hlog))
        return;

    hlog->nkeys = 0;
    memset(hlog->regv, 0, hlog->regc * sizeof(*hlog->regv));
}

uint8_t *
hlog_data(struct hlog *hlog)
{
    return hlog->regv;
}

uint
hlog_precision(struct hlog *hlog)
{
    return hlog->precision;
}

void
hlog_union(struct hlog *hlog, u8 *new)
{
    uint i;

    assert(hlog);
    assert(new);

    for (i = 0; i < hlog->regc; i++)
        if (hlog->regv[i] < new[i])
            hlog->regv[i] = new[i];
}

void
hlog_add(struct hlog *hlog, u64 hash)
{
    uint i, cnt, nbits;
    u64  bit;

    hlog->nkeys++;

    /* set cnt equal to one more than the number of consecutive
     * between bit 'p' the most significant end of the hash
     */
    bit = 1ull << hlog->precision;
    nbits = 64 - hlog->precision;
    cnt = 1;
    while ((hash & bit) == 0 && cnt <= nbits) {
        cnt++;
        bit <<= 1;
    }

    i = hash & hlog->mask;
    if (cnt > hlog->regv[i])
        hlog->regv[i] = cnt;
}

#if 0
static
int
lookup0(
    double          v,
    const double   *xdata,
    int             xlen)
{
    int i;

    for (i = 1; i < xlen-1; i++)
        if (v < xdata[i])
            break;

    return i - 1;
}
#endif
static int
lookup1(double v, const double *xdata, int xlen)
{
    int i, first, last;

    i = first = 1;
    last = xlen - 2;

    while (first <= last) {
        i = (first + last) / 2;
        if (v < xdata[i])
            last = i - 1;
        else
            first = i + 1;
    }

    return last;
}

static int
hlog_bias_adjust(double est, uint p, double *result)
{
    int    i;
    double x1, y1;
    double x2, y2;
    double m;

    const struct hlog_table *raw;
    const struct hlog_table *bias;

    assert(p >= HLOG_PRECISION_MIN);
    assert(p <= HLOG_PRECISION_MAX);

    raw = rawEstimateData + p;
    bias = biasData + p;

    i = lookup1(est, raw->vec, raw->len);
    assert(i >= 0);
    assert(i + 1 < raw->len);
    assert(i + 1 < bias->len);

    x1 = raw->vec[i];
    y1 = bias->vec[i];

    x2 = raw->vec[i + 1];
    y2 = bias->vec[i + 1];

    /* If the estimate is out of range in the correction table,
     * then we should not use the correction.
     */
    if (i == 0 && est < x1)
        return -1;

    m = (y2 - y1) / (x2 - x1);

    *result = y1 + m * (est - x1);

    return 0;
}

static u64
hlog_card_data(u8 *regv, uint p)
{
    double est, h;
    uint   i, v;
    uint   m = 1 << p;
    double alpha, bias;

    /* opto: precompute, use table */
    assert(p >= 4);
    switch (p) {
        case 4:
            alpha = 0.673 * 16 * 16;
            break;
        case 5:
            alpha = 0.697 * 32 * 32;
            break;
        case 6:
            alpha = 0.709 * 64 * 64;
            break;
        default:
            alpha = (0.7213 / (1.0 + 1.079 / m)) * m * m;
            break;
    }

    v = 0;
    est = 0.0;
    for (i = 0; i < m; i++) {
        est += 1.0 / (1ull << regv[i]);
        if (!regv[i])
            v++;
    }

    est = alpha / est;

    if (est <= 5 * m) {
        if (hlog_bias_adjust(est, p, &bias))
            return m * log(1.0 * m / v);
        assert(est >= bias);
        est -= bias;
    }

    if (v)
        h = m * log(1.0 * m / v);
    else
        h = est;

    if (h <= hlog_lc_threshold[p])
        est = h;

    return est;
}

u64
hlog_card(struct hlog *hlog)
{
    return hlog_card_data(hlog->regv, hlog->precision);
}

#if HSE_MOCKING
#include "hlog_ut_impl.i"
#endif /* HSE_MOCKING */
