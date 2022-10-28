/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_PERFC_H
#define HSE_PLATFORM_PERFC_H

#include <hse/error/merr.h>
#include <hse/util/assert.h>
#include <hse/util/atomic.h>
#include <hse/util/data_tree.h>
#include <hse/util/platform.h>
#include <hse/util/timer.h>

/* clang-format off */

/* MTF_MOCK_DECL(perfc) */

/* Perf counter engagement levels
 */
#define PERFC_LEVEL_MIN     (0)
#define PERFC_LEVEL_MAX     (9)
#define PERFC_LEVEL_DEFAULT (2)

/* PERFC_VALPERCNT          max per-cpu values per counter
 * PERFC_VALPERCPU          max per-cpu values per cacheline
 * PERFC_IVL_MAX            max bounds in a distribution counter
 * PERFC_GRP_MAX            max cpu groups in a distribution counter
 * PERFC_PCT_SCALE          power-of-two scaling factor for pdi_pct
 */
#define PERFC_VALPERCNT     (128)
#define PERFC_VALPERCPU     (HSE_ACP_LINESIZE / sizeof(struct perfc_val))
#define PERFC_VAL_MAX       (PERFC_VALPERCNT * PERFC_VALPERCPU)
#define PERFC_IVL_MAX       (32 - 1)
#define PERFC_GRP_MAX \
    ((PERFC_VALPERCNT * HSE_ACP_LINESIZE) / ((PERFC_IVL_MAX + 1) * sizeof(struct perfc_bkt)))

#define PERFC_PCT_SCALE     (1u << 20)
#define PERFC_CTRS_MAX      (64)

#define PERFC_DT_PATH       "/data/perfc"

/* If you perturb perfc_type in any way then be certain to update
 * perfc_ctr_name2type() and perfc_ctr_type2name[] to match.
 */
enum perfc_type {
    PERFC_TYPE_INVAL,
    PERFC_TYPE_BA, /* Get the value of a variable */
    PERFC_TYPE_RA, /* Get the rate or gradient of a variable */
    PERFC_TYPE_LT, /* Get the distribution of a latency */
    PERFC_TYPE_DI, /* Get the distribution of a variable */
    PERFC_TYPE_SL, /* Simple latency, cumulative average */
};

enum perfc_ctr_flags {
    PCC_FLAGS_ENABLED   = 0x1,
    PCC_FLAGS_WRITEABLE = 0x2,
    PCC_FLAGS_ALLOCATED = 0x4
};

#define PCC_FLAGS_ALL   (PCC_FLAGS_ENABLED | PCC_FLAGS_WRITEABLE | PCC_FLAGS_ALLOCATED)

#define NE0(_name, _pri, _desc, _hdr) \
    [_name] = {                       \
        .pcn_name = #_name,           \
        .pcn_desc = (_desc),          \
        .pcn_hdr = (_hdr),            \
        .pcn_flags = PCC_FLAGS_ALL,   \
        .pcn_prio = (_pri),           \
        .pcn_samplepct = 100,         \
    }

#define NE1(_name, _pri, _desc, _hdr, _pct) \
    [_name] = {                             \
        .pcn_name = #_name,                 \
        .pcn_desc = (_desc),                \
        .pcn_hdr = (_hdr),                  \
        .pcn_flags = PCC_FLAGS_ALL,         \
        .pcn_prio = (_pri),                 \
        .pcn_samplepct = (_pct),            \
    }

#define EV_GET_NEMACRO(_0, _1, NAME, ...) NAME
#define NE(_name, _pri, _desc, _hdr, ...) \
    EV_GET_NEMACRO(_0, ##__VA_ARGS__, NE1, NE0)(_name, _pri, _desc, _hdr, ##__VA_ARGS__)

#define NE_CHECK(_arr, _max, _msg) \
    static_assert((NELEM((_arr)) == (_max) && NELEM((_arr)) < PERFC_CTRS_MAX), _msg)

/* clang-format on */

struct perfc_ivl;

/**
 * perfc_init() - Initialize the perfc subsystem
 *
 * Creates the /data/perfc node.
 */
merr_t
perfc_init(void) HSE_COLD;

/**
 * perfc_fini() - Initialize the perfc subsystem
 *
 * Removes the /data/perfc node.
 */
void
perfc_fini(void) HSE_COLD;

/**
 * perfc_ivl_create() - create a dis/lat counter interval object
 * @boundc:   number of elements in boundv[]
 * @boudnv:   vector of interval boundardies
 * @ivlp:     ptr to ptr to bounds object
 */
/* MTF_MOCK */
merr_t
perfc_ivl_create(int boundc, const u64 *boundv, struct perfc_ivl **ivlp);

/**
 * perfc_ivl_destroy() - destroy a dis/lat counter interval object
 * @ivl:  interval object to destroy
 */
void
perfc_ivl_destroy(struct perfc_ivl *ivl);

/*
 *
 * Below are the definition when the leaf node of the data tree is a
 * a counter set instance (as opposed to a counter instance).
 *
 */

/*
 *   ----------                     --------------------
 *   |        |                     |                  |
 *   | Family |---------------------| Counter set      |
 *   |        |                     | (definition of a |
 *   |        |                     | set of counters) |
 *   |        |                     |                  |
 *   ----------                     --------------------
 *                                      /        \
 *                                     /          \
 *                                    /            \
 *                                   /              \
 *                                  /                \
 *                                 /                  \
 *                          ---------------       ----------------
 *                          |             |       |              |
 *                          | Counter set |       | Counter set  |
 *                          | instance    |       | instance     |
 *                          |             |       |              |
 *                          ---------------       ----------------
 *
 *
 *
 *
 * How the counters are grouped?
 * =============================
 * Counters are grouped per family. A family is a set of counters.
 * For example the family "PD" contains the counters related to a PD,
 * and the family "MPOOL" contains the counters gloabl to a mpool.
 * A family is uniquely identified by its name ("PD" or "MPOOL" for
 * example.
 * It is not mandatory, but a family is related to a subcomponent of the client.
 * Doing so allow to map a set of counters (a family) to a synchronization
 * domain of the client. We see later the advantage of that.
 * Grouping counters per family reduces a lot the code bloat in the client
 * code using performance counters.
 * For example consider 20 counters are used to monitor a PD. The application
 * mpool PD code, instead of having 20 pointers (one on each counter), has
 * only on pointer on a counter set instance. And the counter
 * set instance has itself 20 counters. The counter set instance is an instance
 * of the 20 counters of the family PD.
 *
 * Counter set instance
 * ====================
 * The counter set of a family is instantiated.
 * Coming back to the family PD, mpool creates  a counter set intance for each
 * PD. This is to be able to monitor individually each PD.
 *
 * Placement of the counters in the performance data tree
 * ======================================================
 * A counter is not represented by a node in the tree.
 * It is a counter set instance that is mapped to a [leaf] node.
 * As a consequence the granularity of retrieval from the tree is
 * the counter set instance.
 * To come back to the PD example, the user space can fetch at minimum
 * all the counters of a particular PD. It can't retrieve only a particular
 * counter of a particular PD.
 * The downside of this approach is that you cannot use the REST path
 * to select a specific counter.
 *
 * Synchronization
 * ===============
 * Basic and rate counters are per-cpu counters, updated atomically, and
 * eventually consistent.  Hence they are 100% accurate, but may be
 * inconsistent amongst themselves at any given sampling of their values.
 * If it is important to keep the counter synchronized with other counters, the
 * preferred  way to do it
 * is to  to place the counter update inside an existing section of application
 * code already serialized by application locks.
 * This is helped by matching counter families with application synchronization
 * domains.
 *
 * How to add performance counter?
 * ===============================
 *
 * Two ways:
 * a) Create a new counter family.
 * b) Add a counter to an existing counter family.
 *
 * Adding a new counter family
 * ===========================
 * 1) Choose a familyname. All upper case and without '_' or spaces.
 *    We call it <FAMILYNAME>.
 *    <familyname> is the same thing but in lower case.
 *
 * 2) Choose a counter name and a counter description for each counter of the
 *    family.
 *    The name must follow the syntax described later.
 *    In particular, a portion of the name decides the type of counter.
 *    The counter name is also the index (i.e., the "cid") in the counter set.
 *
 * 3) In an application header file, define the enum used to index the
 *    counters in the set.
 *    The enum members names are the names of the counters in the set.
 *    The enum is as below:
 *
 * enum <cpn>_perfc_cidx_<familyname> {
 *      <counter1 name>,
 *              .
 *      <countern name>,
 *      PERFC_EN_<FAMILYNAME>
 * };
 *    <cpn> is the name of the component using the counters.
 *
 * In the same header file add:
 * extern struct perfc_name <cpn>_perfc_ctrnames_<familyname>[];
 *
 *
 * 4) In an application C file place the family counters names and descriptions
 *    in an array.
 *
 * struct perfc_name <cpn>_perfc_ctrnames_<familyname> [] = {
 *      NE(<counter1 name>, <counter1 description>),
 *                 .
 *      NE(<countern name>, <countern description>)
 * };
 *
 * NE_CHECK(<cpn>_perfc_ctrnames_<famname>, PERFC_EN_<FAMNAME>,
 *          "<cpn>_perfc_ctrnames_<familyname> table/enum mismatch");
 *
 *
 * 5) Instantiate a set of counters of the family
 *
 *    To use this family of counters, one or several instances of its counter
 *    set must be created.
 *    This is done by calling perfc_alloc(). Each call creates
 *    a counter set instance. A pointer on the instance is returned
 *    (parameter "set").
 *    Save this pointer in an application stucture. It will be used later
 *    when the application updates a counter.
 *
 *    A counter set instance is owned by the application. It is the application
 *    that decides when to create it, use it and free it.
 *
 * 6) Update of counters by the application.
 *
 *    The application calls one of the following inline functions:
 *    perfc_set(), perfc_lat_record(), perfc_dis_record(), perfc_inc(),
 *    perfc_dec(), perfc_add(), perfc_sub().
 *    The parameters of these functions are the counter set instance pointer,
 *    the index of the counter in the set, and, for some of the macro, a value.
 *
 * 7) Free an instance of a counter set
 *
 *    When the counters are not used anymore (for example the mpool is
 *    unmounted), the counters should be freed else we would get a
 *    memory leak.
 *    To free a counter instance, the application call perfc_ctrseti_free().
 *    After the free, the application should not access the counter set
 *    instance.
 *
 * Adding a counter in an existing family
 * ======================================
 * 1) Add a member in the enum representing the index in the counter set.
 *    The enum is of the form:
 * enum <cpn>_perfc_cidx_<familyname> {
 *      .
 * };
 *    The name of this new member is also the counter name.
 *    This name must follow the naming syntax described below.
 *
 * 2) Add a line in the array containing the family counters names and
 *    description.
 *    This array is of the form:
 * struct perfc_name <cpn>_perfc_ctrnames_<familyname> [] = {
 *      .
 *      NE(<counteri name>, <counteri description>),
 *      .
 * };
 *
 * 3) In the application code, calls one of the inline functions perfc_xxx()
 *    to update the counter as you whish. For example call perfc_inc().
 */

/*
 * Counter name syntax.
 *
 * Naming convention for the names of counters of a family.
 * These names are also the indexes in a counter set.
 * They are all upper case.
 *
 * Start with PERFC_
 *
 * Followed by the type of counter:
 * BA_ basic counter
 * RA_ rate counter
 * DI_ distribution counter
 * LT_ distribution of a latency counter
 * SL_ simple latency counter
 *
 * Followed with <FAMILYNAME>_ that identifies the family of the counter.
 *
 * Followed with the counter meaning.
 *
 * For example: PERFC_LT_MPOOL_MB_READ
 *      family is "MPOOL".
 */

/* The perfc "rollup" macros are similar to their namesakes with
 * the exception that they only update the specified counter(s)
 * once every ru.cnt calls (i.e., a rollup update).
 * The purpose of this is to reduce (by orders of magnitude) the
 * impact to the system of maintaining a hot perf counter that
 * is accurate.  The downside is that in a release buld it often
 * lags the true value since each thread that calls it might have
 * hits that are not currently reflected in the counter.
 * Additionally, if a thread exited with pending hits then those
 * hits will be forever lost.
 */

/* The rollup code is tested explicitly in perfc_test.c,
 * no need to test coverage at each call site.
 */
/* GCOV_EXCL_START */

#ifdef HSE_BUILD_RELEASE
#define PERFC_RU_MAX        (128)

#define PERFC_INC_RU(_pc, _cid)                         \
    do {                                                \
        static thread_local struct {                    \
            u64 cnt;                                    \
        } ru;                                           \
                                                        \
        if (HSE_UNLIKELY(++ru.cnt >= PERFC_RU_MAX)) {   \
            perfc_add((_pc), (_cid), ru.cnt);           \
            ru.cnt = 0;                                 \
        }                                               \
    } while (0)

#define PERFC_INCADD_RU(_pc, _cidx1, _cidx2, _val2)                     \
    do {                                                                \
        static thread_local struct {                                    \
            u64 cnt;                                                    \
            u64 sum;                                                    \
        } ru;                                                           \
                                                                        \
        ru.sum += (_val2);                                              \
                                                                        \
        if (HSE_UNLIKELY(++ru.cnt >= PERFC_RU_MAX)) {                   \
            perfc_add2((_pc), (_cidx1), ru.cnt, (_cidx2), ru.sum);      \
            ru.cnt = 0;                                                 \
            ru.sum = 0;                                                 \
        }                                                               \
    } while (0)

#define PERFC_DEC_RU(_pc, _cid)                         \
    do {                                                \
        static thread_local struct {                    \
            u64 cnt;                                    \
        } ru;                                           \
                                                        \
        if (HSE_UNLIKELY(++ru.cnt >= PERFC_RU_MAX)) {   \
            perfc_sub((_pc), (_cid), ru.cnt);           \
            ru.cnt = 0;                                 \
        }                                               \
    } while (0)

#else

#define PERFC_INC_RU(_pc, _cid) \
    perfc_inc((_pc), (_cid))

#define PERFC_INCADD_RU(_pc, _cidx1, _cidx2, _val2) \
    perfc_add2((_pc), (_cidx1), 1, (_cidx2), (_val2))

#define PERFC_DEC_RU(_pc, _cid) \
    perfc_dec((_pc), (_cid))

#endif

/* GCOV_EXCL_STOP */

/* clang-format on */

/**
 * struct perfc_ivl - interval bounds map
 * @ivl_cnt:    length of ivl_bound[] vector
 * @ivl_map:    used to map ipow2(val) to the nearest bound[]
 * @il_bound:   vector of interval boundaries
 */
struct perfc_ivl {
    u8  ivl_cnt;
    u8  ivl_map[63];
    u64 ivl_bound[];
};

/**
 * struct perfc_name -
 * @pcn_name:
 * @pcn_desc:
 * @pcn_hdr:        column header for the counter
 * @pcn_flags:
 * @pcn_prio:       counter priority level
 * @pcn_samplepct:  dis/lat counter sample record percentage
 * @pcn_ivl:        dis/lat interval bounds
 *
 * %pcn_ivl is used only for distribution/latency counters, can be nil
 * for all other counter types.
 */
struct perfc_name {
    const char *      pcn_name;
    const char *      pcn_desc;
    const char *      pcn_hdr;
    uint8_t           pcn_flags;
    uint8_t           pcn_prio;
    uint32_t          pcn_samplepct;
    struct perfc_ivl *pcn_ivl;
};

/**
 * struct perfc_val - per-cpu value for basic and rate counters
 * @pcv_vadd:   used by perfc_inc, perfc_add
 * @pcv_vsub:   used by perfc_dec, perfc_sub
 *
 * perc_ctr_hdr contains a per-cpu vector of perfc_val objects.
 * This struct is cacheline aligned so as to prevent false sharing,
 * but note that perfc_bkt leverages this fact to use the space
 * that is otherwise wasted by basic and rate counters.
 */
struct perfc_val {
    atomic_ulong pcv_vadd;
    atomic_ulong pcv_vsub;
};

/**
 * struct perfc_bkt - per-node data for distribution counters
 * @pcv_vadd:   sum of samples for this bucket
 * @pcv_hits:   number of sample in this bucket
 *
 * perc_ctr_hdr contains a vector of perfc_bkt objects which are
 * accessed by sub groups of cpus.  The performance hit due to
 * false-sharing between buckets within a group is eclipsed by
 * the performance improvement obtained by the reduction of
 * cacheline thrashing between cpus.
 */
struct perfc_bkt {
    atomic_ulong pcb_vadd;
    atomic_ulong pcb_hits;
};

/**
 * struct perfc_ctr_hdr - per counter data
 * @pch_type:       counter type (basic, rate, distribution, ...)
 * @pch_flags:      counter flags
 * @pch_val:        per-cpu values for basic and rate counters
 * @pch_bkt:        distribution counter bucket data (per-cpu node)
 *
 * For basic and rate counters there is one pch_val[] per cpu (modulo
 * PERFC_VALPERCNT).  For distribution counters each pch_val[] object
 * constitutes one bucket in the distribution.
 */
struct perfc_ctr_hdr {
    enum perfc_type     pch_type;
    u32                 pch_flags;
    u32                 pch_level;

    union {
        struct perfc_val   *pch_val;
        struct perfc_bkt   *pch_bktv;
    };
};

/**
 * struct perfc_basic - basic counter
 * @pcb_hdr:    base counter object
 *
 * perfc_basic "is-a" perfc_ctr_hdr.
 */
struct perfc_basic {
    struct perfc_ctr_hdr pcb_hdr; /* Must be first field */
};

/**
 * struct perfc_rate - rate counter
 * @pcr_hdr:    base counter object
 * @pcr_old_val:
 * @pcr_old_time_ns:
 *
 * perfc_rate "is-a" perfc_ctr_hdr.
 */
struct perfc_rate {
    struct perfc_ctr_hdr pcr_hdr; /* Must be first field */
    u64                  pcr_old_val;
    u64                  pcr_old_time_ns;
};

/**
 * struct perfc_dis - distribution/latency counter
 * @pdi_hdr:    base counter object
 * @pdi_min:    overall minimum value in distribution
 * @pdi_max:    overall maximum value in distribution
 * @pdi_ivl:    distribution bucket bounds
 *
 * perfc_dis "is-a" perfc_ctr_hdr.
 */
struct perfc_dis {
    struct perfc_ctr_hdr    pdi_hdr; /* Must be first field */
    u32                     pdi_pct;
    u64                     pdi_min;
    u64                     pdi_max;
    const struct perfc_ivl *pdi_ivl;
};

/**
 * union perfc_ctru - union of all perf counter types
 */
union perfc_ctru {
    struct perfc_ctr_hdr hdr;
    struct perfc_basic   basic;
    struct perfc_rate    rate;
    struct perfc_dis     dis;
} HSE_L1D_ALIGNED;

/**
 * struct perfc_set - (struct perfc_set *) is a counter set instance handle.
 * @ps_seti:   pointer to the counterset instance
 * @ps_bitmap: a bitmap of enabled counters in the set
 *
 * Note: This struct is in a header file so components can use counters by
 * adding the struct instance to the host struct. But the component should NOT
 * access the members directly. Instead, use either variant of PERFC_ISON() to
 * determine if the counter is enabled:
 *     PERFC_ISON(&set); // whether or not any counter in this set is enabled
 *     PERFC_ISON(&set, cidx); // whether or not the cidx-th counter of this
 *                             // set is enabled
 */
struct perfc_set {
    u64                ps_bitmap;
    struct perfc_seti *ps_seti;
};

/**
 * perfc_seti - One such structure allocated per counter set instance.
 * @pcs_path:          full path of counterset
 * @pcs_famname:       name of family counter set instance belongs to...
 * @pcs_ctrseti_name:  name of this counter set instance
 * @pcs_ctrc:          number of elements in pcs_ctrv[] and pcs_ctrnames[]
 *                     It is also PERFC_EN_<FAMILYNAME>.
 * @pcs_handle:        where the counter set handle is stored. In the client
 *                     memory. This client memory should not be freed before the
 *                     counter set is freed (perfc_ctrseti_free()).
 *                     The counter set handle (*pcs_handle) is updated each time
 *                     the counter is enabled or disabled.
 * @pcs_ctrnamev:      vector of counter names
 * @pcs_ctrv:          vector of counter objects
 *
 * Internal structure corresponding to a handle struct perfc_set.
 */
struct perfc_seti {
    char                     pcs_path[DT_PATH_MAX];
    char                     pcs_famname[DT_PATH_ELEMENT_MAX];
    char                     pcs_ctrseti_name[DT_PATH_ELEMENT_MAX];
    u32                      pcs_ctrc;
    struct perfc_set *       pcs_handle;
    const struct perfc_name *pcs_ctrnamev;
    union perfc_ctru         pcs_ctrv[];
};

/**
 * perfc_lat_record_impl() - Record a latency sample to get its distribution
 *
 * @dis:      distribution performance counter ptr
 * @sample:   sample to record
 *
 * %sample is the latency start time obtained by calling perfc_lat_start().
 */
void
perfc_lat_record_impl(struct perfc_dis *dis, u64 sample);

/**
 * perfc_dis_record_impl() - Record a sample to get its distribution
 *
 * @dis:      distribution performance counter ptr
 * @sample:   sample to record
 *
 * %sample is just whatever data the caller wants to
 * put into the histogram.
 */
void
perfc_dis_record_impl(struct perfc_dis *dis, u64 sample);

/**
 * perfc_read() - return sum totals of all operations made to a counter
 * @pcs:    perfc counter set handle
 * @cidx:   counter index
 * @vadd:   sum of all perfc_inc() and perfc_add() calls
 * @sub:    sum of all perfc_dec() and perfc_sub() calls
 *
 * Reading a perf counter that is actively being updated may return
 * results in %vadd and/or %vsub that are lower than expected.
 * However, results are eventually consistent.
 */
void
perfc_read(struct perfc_set *pcs, const u32 cidx, u64 *vadd, u64 *vsub);


/* [HSE_REVISIT] Add unit tests for all these predicates...
 */
/* GCOV_EXCL_START */

static HSE_ALWAYS_INLINE struct perfc_seti *
PERFC_ISON(struct perfc_set *pcs)
{
    if (pcs && pcs->ps_bitmap > 0)
        return pcs->ps_seti;

    return NULL;
}

/**
 * perfc_ison() - test if specified counter is enabled
 * @pcs:    perfc counter set handle
 * @cidx:   counter index
 *
 * Return: NULL if not enabled, otherwise ptr to counter
 * implementation object.
 */
static HSE_ALWAYS_INLINE struct perfc_seti *
perfc_ison(struct perfc_set *pcs, u32 cidx)
{
    if (pcs && pcs->ps_bitmap & (1ull << cidx))
        return pcs->ps_seti;

    return NULL;
}

/**
 * perfc_lat_start() - acquire latency measurement start time
 * @pcs:    perfc counter set handle
 *
 * Prefer perfc_lat_startu() or perfc_lat_startl() for optimal code
 * generation based on whether the counter is enabled by default.
 *
 * Return: 0 if no counters from the family are enabled, otherwise
 * returns the current time in nanoseconds
 */
static HSE_ALWAYS_INLINE u64
perfc_lat_start(struct perfc_set *pcs)
{
    return PERFC_ISON(pcs) ? get_cycles() : 0;
}

/**
 * perfc_lat_startu() - acquire latency measurement start time
 * @pcs:    perfc counter set handle
 * @cidx:   counter index
 *
 * Assumes the counter is unlikely to be enabled.
 *
 * Return: 0 if the given counter is not enabled, otherwise
 * returns the current time in nanoseconds
 */
static HSE_ALWAYS_INLINE u64
perfc_lat_startu(struct perfc_set *pcs, const u32 cidx)
{
    struct perfc_seti *pcsi;

    pcsi = perfc_ison(pcs, cidx);
    if (HSE_UNLIKELY(pcsi))
        return get_cycles();

    return 0;
}

/**
 * perfc_lat_startl() - acquire latency measurement start time
 * @pcs:    perfc counter set handle
 * @cidx:   counter index
 *
 * Assumes the counter is likely to be enabled.
 *
 * Return: 0 if the given counter is not enabled, otherwise
 * returns the current time in nanoseconds
 */
static HSE_ALWAYS_INLINE u64
perfc_lat_startl(struct perfc_set *pcs, const u32 cidx)
{
    struct perfc_seti *pcsi;

    pcsi = perfc_ison(pcs, cidx);
    if (HSE_LIKELY(pcsi))
        return get_cycles();

    return 0;
}

/**
 * perfc_lat_record() - record a latency distribution measurement
 */
static HSE_ALWAYS_INLINE void
perfc_lat_record(struct perfc_set *pcs, const u32 cidx, const u64 start)
{
    struct perfc_seti *pcsi;

    if (!start)
        return;

    pcsi = perfc_ison(pcs, cidx);
    if (pcsi)
        perfc_lat_record_impl(&pcsi->pcs_ctrv[cidx].dis, start);
}

/**
 * perfc_sl_record() - record a simple latency measurement
 */
static HSE_ALWAYS_INLINE void
perfc_sl_record(struct perfc_set *pcs, const u32 cidx, const u64 start)
{
    struct perfc_ctr_hdr   *hdr;
    struct perfc_seti      *pcsi;
    u64                     val;
    uint                    i;

    if (!start)
        return;

    pcsi = perfc_ison(pcs, cidx);
    if (!pcsi)
        return;

    hdr = &pcsi->pcs_ctrv[cidx].hdr;
    assert(hdr->pch_type == PERFC_TYPE_SL);

    val = cycles_to_nsecs(get_cycles() - start);

    i = hse_getcpu(NULL) % PERFC_VALPERCNT;
    i *= PERFC_VALPERCPU;

    atomic_add(&hdr->pch_val[i].pcv_vadd, val); /* sum */
    atomic_inc(&hdr->pch_val[i].pcv_vsub);      /* hitcnt */
}

/**
 * perfc_dis_record() - record a distribution sample
 */
static HSE_ALWAYS_INLINE void
perfc_dis_record(struct perfc_set *pcs, const u32 cidx, const u64 val)
{
    struct perfc_seti *pcsi;

    pcsi = perfc_ison(pcs, cidx);
    if (pcsi)
        perfc_dis_record_impl(&pcsi->pcs_ctrv[cidx].dis, val);
}

/**
 * perfc_set() - set a counter to the given value
 * @pcs:    counter set ptr
 * @cidx:   counter index
 * @val:    value to set
 *
 * [HSE_REVISIT] This function only sets the first per-cpu value
 * in the counter and does not zero the remaining per-cpu values.
 * Therefore, it should not be freely intermixed with calls to
 * perfc_{inc,dec,add,sub} (except by calling it once after the
 * counter is created before any of the other perfc functions).
 */
static inline void
perfc_set(struct perfc_set *pcs, const u32 cidx, const u64 val)
{
    struct perfc_seti *pcsi;

    pcsi = perfc_ison(pcs, cidx);
    if (!pcsi)
        return;

    atomic_set(&pcsi->pcs_ctrv[cidx].hdr.pch_val[0].pcv_vadd, val);
    atomic_set(&pcsi->pcs_ctrv[cidx].hdr.pch_val[0].pcv_vsub, 0);
}

/* Increment a performance counter.
 */
static HSE_ALWAYS_INLINE void
perfc_inc(struct perfc_set *pcs, const u32 cidx)
{
    struct perfc_seti  *pcsi;
    uint                i;

    pcsi = perfc_ison(pcs, cidx);
    if (!pcsi)
        return;

    i = hse_getcpu(NULL) % PERFC_VALPERCNT;
    i *= PERFC_VALPERCPU;

    atomic_add(&pcsi->pcs_ctrv[cidx].hdr.pch_val[i].pcv_vadd, 1);
}

/* Decrement a performance counter.
 */
static HSE_ALWAYS_INLINE void
perfc_dec(struct perfc_set *pcs, const u32 cidx)
{
    struct perfc_seti  *pcsi;
    uint                i;

    pcsi = perfc_ison(pcs, cidx);
    if (!pcsi)
        return;

    i = hse_getcpu(NULL) % PERFC_VALPERCNT;
    i *= PERFC_VALPERCPU;

    atomic_add(&pcsi->pcs_ctrv[cidx].hdr.pch_val[i].pcv_vsub, 1);
}

/* Add a value to a performance counter.
 */
static HSE_ALWAYS_INLINE void
perfc_add(struct perfc_set *pcs, const u32 cidx, const u64 val)
{
    struct perfc_seti  *pcsi;
    uint                i;

    pcsi = perfc_ison(pcs, cidx);
    if (!pcsi)
        return;

    i = hse_getcpu(NULL) % PERFC_VALPERCNT;
    i *= PERFC_VALPERCPU;

    atomic_add(&pcsi->pcs_ctrv[cidx].hdr.pch_val[i].pcv_vadd, val);
}

/* Add values to two performance counters from the same family.
 */
static HSE_ALWAYS_INLINE void
perfc_add2(struct perfc_set *pcs, const u32 cidx1, const u64 val1, const u32 cidx2, const u64 val2)
{
    struct perfc_seti  *pcsi;
    uint                i;

    pcsi = perfc_ison(pcs, cidx1);
    if (!pcsi)
        return;

    i = hse_getcpu(NULL) % PERFC_VALPERCNT;
    i *= PERFC_VALPERCPU;

    atomic_add(&pcsi->pcs_ctrv[cidx1].hdr.pch_val[i].pcv_vadd, val1);

    if (pcs->ps_bitmap & (1ull << cidx2))
        atomic_add(&pcsi->pcs_ctrv[cidx2].hdr.pch_val[i].pcv_vadd, val2);
}

/* Subtract a value from a performance counter.
 */
static HSE_ALWAYS_INLINE void
perfc_sub(struct perfc_set *pcs, const u32 cidx, const u64 val)
{
    struct perfc_seti  *pcsi;
    uint                i;

    pcsi = perfc_ison(pcs, cidx);
    if (!pcsi)
        return;

    i = hse_getcpu(NULL) % PERFC_VALPERCNT;
    i *= PERFC_VALPERCPU;

    atomic_add(&pcsi->pcs_ctrv[cidx].hdr.pch_val[i].pcv_vsub, val);
}

/* GCOV_EXCL_STOP */

extern struct perfc_ivl *perfc_di_ivl;

#define perfc_alloc(_ctrv, _group, _name, _prio, _setp)                \
    perfc_alloc_impl((_prio), (_group), (_ctrv), NELEM((_ctrv)),       \
                     (_name), REL_FILE(__FILE__), __LINE__, (_setp))

/*
 * perfc_alloc_impl() - allocate a counter set instance
 *      And insert it (leaf node) in the data tree.
 *        /data/perfc/<group>/<FAMILYNAME>/<ctrsetname>
 *      Typically:
 *        /data/perfc/kvdb/0/kvs/mykvs/<FAMILYNAME>/set
 *
 * @prio: the level at and above which the counter should be engaged
 * @name: typically the name of the mpool (its uuid).
 * @ctrnames: name and description of each the counter in the set.
 *      This table should no be freed by the caller till the counter set
 *      instances are removed. Because this table will continue to be
 *      referenced after perfc_alloc() returns.
 * @nbctr: number of elements in ctrnames[].
 * @ctrseti_name: string that identifies the counter set instance.
 *      It must be unique for a given path /data/perfc/<component>/<name>
 *      The path to the set is /data/perfc/<component>/<name>/<setid>
 * @flags: for each counters flags writable and enabled
 *      The size of this array must be the number of counters in the set.
 *      Flags are described by enum perfc_ctr_flags.
 *      Also contains the intervals for distribution and latency counters.
 * @set: where the counter set handle is stored in the caller
 *      memory. The memory at "set" should not be freed before the
 *      perfc_ctrseti_free() or perfc_ctrset_invalidate_handle() is called.
 *
 *      The counter set handle (aka *set) is updated each time the counter
 *      is enabled or disabled.
 *      After perfc_ctrset_invalidate_handle() or perfc_ctrseti_free() returns,
 *      it is guaranteed that the address "set" is not acccessed anymore.
 *
 *      When this function returns, *set is relevant only if no error returned.
 *
 * The path to the set instance will be (assuming component is "mpool"):
 * /data/perfc/mpool/<mpool name>/<counter family name>/<counter set name>
 *
 * The family name is extracted from the counter short names.
 *
 * Note: perfc adopts ctrv[], so the caller must ensure the lifetime
 * of ctrv[] until the counter set is freed.
 */
/* MTF_MOCK */
merr_t
perfc_alloc_impl(
    uint                     prio,
    const char              *group,
    const struct perfc_name *ctrv,
    size_t                   ctrc,
    const char              *name,
    const char              *file,
    int                      line,
    struct perfc_set *       set);

/**
 * perfc_free() - free a counter set instance.
 * @set:
 */
extern void
perfc_free(struct perfc_set *set);

/*
 * perfc_ctrseti_path() - return the path to this counter set
 * @set: the set returned by perfc_alloc()
 */
extern char *
perfc_ctrseti_path(struct perfc_set *set);

#if HSE_MOCKING
#include "perfc_ut.h"
#endif /* HSE_MOCKING */

#endif /* HSE_PLATFORM_PERFC_H */
