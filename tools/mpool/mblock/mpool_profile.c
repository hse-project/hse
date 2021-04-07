/*
 * Copyright (C) 2020 Micron Technology, Inc. All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/page.h>
#include <hse_util/workqueue.h>

#include <mpool/mpool.h>

#include <math.h>

#define KiB (1024UL)
#define MiB (1024UL * KiB)
#define GiB (1024UL * MiB)

/* We use 128KiB writes in all cases */
#define MP_PROF_BLOCK_SIZE (128UL * KiB)

/* Each thread will allocate, fill, and abort/discard MP_PROF_MBLOCKS_PER_THREAD mblocks */
#define MP_PROF_MBLOCKS_PER_THREAD 40

/* Although we allocate & discard, we need the drive to have spare capacity */
#define MP_SPARE_MBLOCKS_PER_THREAD 20

#define MIN_EXPECTED_LAT_NS (1L)
#define MAX_EXPECTED_LAT_NS (10L * 1000L * 1000L * 1000L)

struct mp_profile_work {
    struct work_struct    work_elem;
    struct mpool         *mp;
    enum mp_media_classp  mc;
    int                   tid;
    u32                   mblock_cnt;
    u64                   mblock_sz;
    u64                   block_sz;
    merr_t                err;
    u64                  *samples;
};

struct mp_prof_stat {
    double latmean;
    double latsigma;
};

double
score_prof_stat(
    struct mp_prof_stat *mp_ps)
{
    double mean_us = mp_ps->latmean / 1000.0;
    double sigma_us = mp_ps->latsigma / 1000.0;
    double sigma2mean = sigma_us / mean_us;

    if ((mean_us < 3000.0 && sigma2mean < 1.5) ||
        (mean_us < 6000.0 && sigma2mean < 1.2))
        return 0.0;
    else if ((mean_us <  6000.0 && sigma2mean < 1.5) ||
             (mean_us <  8000.0 && sigma2mean < 1.2) ||
             (mean_us < 10000.0 && sigma2mean < 1.0) ||
             (mean_us < 12000.0 && sigma2mean < 0.7) ||
             (mean_us < 15000.0 && sigma2mean < 0.5))
        return 1.0;
    else
        return 2.0;
}

void
profile_worker(
    struct work_struct *arg)
{
    struct mp_profile_work *work;
    struct mpool           *mp;
    enum mp_media_classp    mc;
    u32                     mblock_cnt;
    u64                     mblock_sz;
    u64                     block_sz;
    u64                    *samples;
    struct iovec            iov;
    void                   *buf;
    u64                     start, stop;
    struct mblock_props     mbprop;
    u64                     handle;
    merr_t                  err = 0;
    u32                     i, sample_idx;
    char                    errbuf[160];
    int                     block, num_blocks;

    work = container_of(arg, struct mp_profile_work, work_elem);

    buf = alloc_aligned(PAGE_SIZE, work->block_sz);
    if (!buf) {
        fprintf(stderr, "alloc_aligned() failed for %lu bytes, page aligned\n", work->block_sz);
        work->err = ENOMEM;

        return;
    }

    mp         = work->mp;
    mc         = work->mc;
    mblock_cnt = work->mblock_cnt;
    mblock_sz  = work->mblock_sz;
    block_sz   = work->block_sz;
    samples    = work->samples;

    sample_idx = 0;
    num_blocks = mblock_sz / block_sz;

    for (block = 0; block < mblock_cnt; ++block) {
        err = mpool_mblock_alloc(mp, mc, &handle, &mbprop);
        if (err) {
            merr_strerror(err, errbuf, sizeof(errbuf));
            fprintf(stderr, "mpool_mblock_alloc() failed: %s\n", errbuf);
            work->err = merr_errno(err);

            break;
        }

        for (i = 0; i < num_blocks; i++) {
            iov.iov_base = buf;
            iov.iov_len = block_sz;

            start = get_time_ns();

            err = mpool_mblock_write(mp, handle, &iov, 1);
            if (err) {
                merr_strerror(err, errbuf, sizeof(errbuf));
                fprintf(stderr, "mpool_mblock_write() failed: %s\n", errbuf);
                work->err = err;
                break;
            }

            stop = get_time_ns();

            samples[sample_idx++] = stop - start;
        }

        err = mpool_mblock_abort(mp, handle);
        if (err) {
            merr_strerror(err, errbuf, sizeof(errbuf));
            fprintf(stderr, "mpool_mblock_abort() failed: %s\n", errbuf);
            if (work->err == 0)
                work->err = err;

            break;
        }
    }

    free_aligned(buf);

    return;
}

int
perform_profile_run(
    struct mpool        *mp,
    enum mp_media_classp mc,
    u32                  thread_cnt,
    u32                  mblocks_per_thread,
    u64                  mblock_sz,
    u64                  block_sz,
    double              *score)
{
    struct workqueue_struct *workqueue;
    struct mp_profile_work  *work_specs;
    int                      error_seen = 0;
    int                      i, j;
    const u32                samples_per_thread = mblocks_per_thread * (mblock_sz / block_sz);
    struct mp_prof_stat      stats;
    u64                      sum;
    double                   tmp, var_sum;
    double                   mean;
    double                   sigma;
    char                     errbuf[160];

     workqueue = alloc_workqueue("mpool_profiling_wq", 0, thread_cnt);
    if (!workqueue)
        return ENOMEM;

    work_specs = malloc(thread_cnt * sizeof(struct mp_profile_work));
    if (!work_specs) {
        destroy_workqueue(workqueue);
        return ENOMEM;
    }

    /* prepare the per-thread data */
    for (i = 0; i < thread_cnt; ++i) {
        work_specs[i].mp         = mp;
        work_specs[i].mc         = mc;
        work_specs[i].tid        = i;
        work_specs[i].mblock_cnt = mblocks_per_thread;
        work_specs[i].mblock_sz  = mblock_sz;
        work_specs[i].block_sz   = block_sz;
        work_specs[i].err        = 0;

        work_specs[i].samples = malloc(samples_per_thread * sizeof(double));
        if (!work_specs[i].samples) {
            int j;

            for (j = 0; j < i; ++j)
                free(work_specs[i].samples);

            free(work_specs);
            destroy_workqueue(workqueue);

            return -1;
        }

        INIT_WORK(&work_specs[i].work_elem, profile_worker);
    }

    /* launch the threads */
    for (i = 0; i < thread_cnt; ++i)
        queue_work(workqueue, &work_specs[i].work_elem);

    /* wait for them to complete */
    flush_workqueue(workqueue);

    /* process any errors that occurred */
    for (i = 0; i < thread_cnt; ++i) {
        if (work_specs[i].err) {
            error_seen = 1;
            merr_strerror(work_specs[i].err, errbuf, sizeof(errbuf));
            fprintf(stderr, "thread %d experienced mpool error : %s\n",
                    i, errbuf);
        }
    }

    /* if there were one or more errors, bail */
    if (error_seen) {
        for (i = 0; i < thread_cnt; ++i)
            free(work_specs[i].samples);
        free(work_specs);
        destroy_workqueue(workqueue);

        return -1;
    }

    /* process the results from the runs */

    sum = 0UL;
    for (i = 0; i < thread_cnt; ++i)
        for (j = 0; j < samples_per_thread; ++j)
            sum += work_specs[i].samples[j];
    mean = (double)sum / (double)(thread_cnt * samples_per_thread);

    var_sum = 0.0;
    for (i = 0; i < thread_cnt; ++i) {
        for (j = 0; j < samples_per_thread; ++j) {
            tmp = (double)work_specs[i].samples[j] - mean;
            var_sum += tmp * tmp;
        }
    }
    sigma = sqrt(var_sum / (double)(thread_cnt * samples_per_thread));

    stats.latmean  = mean;
    stats.latsigma = sigma;

    *score = score_prof_stat(&stats);

    for (i = 0; i < thread_cnt; ++i)
        free(work_specs[i].samples);

    free(work_specs);
    destroy_workqueue(workqueue);

    return 0;
}

int
profile_mpool(
    const char          *mpname,
    enum mp_media_classp mc,
    u64                  mblock_sz,
    u32                  thread_cnt,
    double              *score)
{
    merr_t              mp_err;
    int                 flags = O_RDWR;
    struct mpool       *mp;
    u64                 block_sz = MP_PROF_BLOCK_SIZE;
    u32                 mblocks_per_thread = MP_PROF_MBLOCKS_PER_THREAD;
    char                errbuf[160];
    int                 rc;

    /* TODO: fix this */
    mp_err = mpool_open(mpname, NULL, flags, &mp);
    if (mp_err) {
        merr_strerror(mp_err, errbuf, sizeof(errbuf));
        fprintf(stderr, "error from mpool_open() : %s\n", errbuf);
        return -1;
    }

    rc = perform_profile_run(mp, mc, thread_cnt, mblocks_per_thread, mblock_sz, block_sz, score);

    mpool_close(mp);

    return rc;
}

struct mp_media_class_info {
    u64 exists;
    u64 total_space;
    u64 mblock_sz;
};

struct mpool_info {
    struct mp_media_class_info mc_info[MP_MED_COUNT];
};

int
get_mpool_info(
    const char        *mpname,
    struct mpool_info *info)
{
    merr_t                    mp_err;
    struct mpool             *mp;
    int                       flags = O_RDWR;
    struct mpool_props        props;
    enum mp_media_classp      mc;
    struct mpool_mclass_props mc_props;
    char                      errbuf[160];

    /* TODO: fix this */
    mp_err = mpool_open(mpname, NULL, flags, &mp);
    if (mp_err) {
        merr_strerror(mp_err, errbuf, sizeof(errbuf));
        fprintf(stderr, "error from mpool_open() : %s\n", errbuf);
        return -1;
    }

    mp_err = mpool_props_get(mp, &props);
    if (mp_err) {
        mpool_close(mp);
        merr_strerror(mp_err, errbuf, sizeof(errbuf));
        fprintf(stderr, "error from mpool_props_get() : %s\n", errbuf);
        return -1;
    }

    mc = MP_MED_STAGING;
    mp_err = mpool_mclass_get(mp, mc, &mc_props);
    if (mp_err) {
        if (merr_errno(mp_err) != ENOENT) {
            mpool_close(mp);
            merr_strerror(mp_err, errbuf, sizeof(errbuf));
            fprintf(stderr, "error from mpool_mclass_get() for STAGING: %s\n", errbuf);
            return -1;
        }

        info->mc_info[MP_MED_STAGING].exists = 0;
        info->mc_info[MP_MED_STAGING].total_space = 0;
    }
    else {
        info->mc_info[MP_MED_STAGING].exists = 1;
        info->mc_info[MP_MED_STAGING].total_space = mc_props.mc_total;
        info->mc_info[MP_MED_STAGING].mblock_sz = props.mp_mblocksz[MP_MED_STAGING] * MiB;
    }

    mc = MP_MED_CAPACITY;
    mp_err = mpool_mclass_get(mp, mc, &mc_props);
    if (mp_err) { /* there must be an MP_MED_CAPACITY media class */
        merr_strerror(mp_err, errbuf, sizeof(errbuf));
        fprintf(stderr, "error from mpool_mclass_get() for CAPACITY : %s\n", errbuf);
        mpool_close(mp);
        return -1;
    }

    info->mc_info[MP_MED_CAPACITY].exists = 1;
    info->mc_info[MP_MED_CAPACITY].total_space = mc_props.mc_total;
    info->mc_info[MP_MED_CAPACITY].mblock_sz = props.mp_mblocksz[MP_MED_CAPACITY] * MiB;

    mpool_close(mp);

    return 0;
}

static void
usage(const char *program)
{
    printf("usage: %s [options] <mpool name>\n", program);

    printf(" -h\tThis help text\n");
    printf(" -v\tMake the output more explanatory\n");
}

int
handle_options(
    int          argc,
    char        *argv[],
    int         *verbose,
    const char **mpname)
{
    const char  options[] = "hv";
    const char *program;
    int         lcl_verbose = 0;

    program = strrchr(argv[0], '/');
    program = program ? program + 1 : argv[0];

    if (argc < 2) {
        usage(program);
        return -1;
    }

    for (;;) {
        char c;

        c = getopt(argc, argv, options);
        if (-1 == c)
            break;

        switch (c) {
          case 'h':
              usage(program);
              exit(0);

          case 'v':
              lcl_verbose = 1;
              break;
        }
    }

    argc -= optind;
    argv += optind;
    if (argc > 1) {
        fprintf(stderr, "Extraneous arguments detected\n");
        usage(program);

        return -1;
    }

    *verbose  = lcl_verbose;
    *mpname = argv[0];

    return 0;
}

int
main(int argc, char *argv[])
{
    const char          *mpname;
    struct mpool_info    info;
    int                  verbose;
    int                  rc;
    int                  thread_counts[] = { 16, 20, 24, 32, 40, 48 };
    const int            num_thread_counts = sizeof(thread_counts)/sizeof(int);
    double               scores[num_thread_counts];
    double               avg_score;
    enum mp_media_classp mc;
    u64                  max_thrds = thread_counts[num_thread_counts - 1];
    u64                  mblock_sz;
    u64                  max_space_needed;
    const char          *result;

    rc = handle_options(argc, argv, &verbose, &mpname);
    if (rc)
        return -1;

    rc = get_mpool_info(mpname, &info);
    if (rc)
        return -1;

    if (info.mc_info[MP_MED_STAGING].exists != 0)
        mc = MP_MED_STAGING;
    else
        mc = MP_MED_CAPACITY;
    mblock_sz = info.mc_info[mc].mblock_sz;

    max_space_needed = max_thrds * MP_SPARE_MBLOCKS_PER_THREAD * mblock_sz;

    if (info.mc_info[mc].total_space < max_space_needed) {
        char *mclass_name = (mc == MP_MED_STAGING) ? "STAGING" : "CAPACITY";
        u32 space_needed_mb = 1 + (max_space_needed / MiB);

        fprintf(stderr,
                "%s media class present but insufficient space available. The\n"
                "profiling test needs %u MiB of free space to characterize mpool\n"
                "performance.", mclass_name, space_needed_mb);
        return -1;
    }

    for (int i = 0; i < num_thread_counts; ++i)
        profile_mpool(mpname, mc, mblock_sz, thread_counts[i], &scores[i]);

    avg_score = 0;
    for (int i = 0; i < num_thread_counts; ++i)
        avg_score += scores[i];
    avg_score = avg_score / num_thread_counts;

    if (avg_score < 0.5)
        result = "light";
    else if (avg_score < 1.2)
        result = "medium";
    else
        result = "default";

    printf("%s\n", result);
    if (!verbose)
        return 0;

    printf("\n");
    printf("The performance profile of mpool %s suggests a setting of \"%s\" for the\n",
           mpname, result);
    printf("kvdb.throttle_init_policy configuration parameter. If you are using the YAML\n");
    printf("config file mechanism this would look like:\n");
    printf("\n");
    printf("api_version: 1\n");
    printf("kvdb:\n");
    printf("  throttle_init_policy: %s\n", result);
    printf("\n");
    printf("along with whatever other configuration settings you already have.\n");
    printf("\n");
    printf("Running HSE with an improper setting for throttle_init_policy (e.g., \"medium\"\n");
    printf("for a slow mpool) will likely cause durability settings to not be honored and\n");
    printf("search data structures to become unbalanced until the throttling catches up.\n");

    return 0;
}
