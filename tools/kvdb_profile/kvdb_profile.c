/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020-2021 Micron Technology, Inc. All rights reserved.
 */

#include <sysexits.h>
#include <math.h>

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/page.h>
#include <hse_util/workqueue.h>
#include <hse_util/string.h>

#include <hse/hse.h>
#include <mpool/mpool.h>


#define KiB (1024UL)
#define MiB (1024UL * KiB)
#define GiB (1024UL * MiB)

/* We use 128KiB writes in all cases */
#define MP_PROF_BLOCK_SIZE (128UL * KiB)

/* Each thread will allocate, fill, and abort/discard MP_PROF_MBLOCKS_PER_THREAD mblocks */
#define MP_PROF_MBLOCKS_PER_THREAD     32

/* Although we allocate & discard, we need the drive to have spare capacity */
#define MP_SPARE_MBLOCKS_PER_THREAD    20

#define MIN_EXPECTED_LAT_NS    (1L)
#define MAX_EXPECTED_LAT_NS    (10L * 1000L * 1000L * 1000L)

#define MP_PROF_TMP_DIR        "kvdb_profile.tmp"


static int test_time_secs = 60;
static bool verbose;
static bool quiet;
static sig_atomic_t sigint;
static sig_atomic_t sigalrm;

struct mpool_info {
    uint64_t total_space;
    uint64_t avail_space;
    uint64_t mblock_sz;
};

struct mp_profile_work {
    struct work_struct work_elem;
    struct mpool      *mp;
    int                tid;
    uint32_t           num_samples;
    uint32_t           mblock_cnt;
    uint64_t           mblock_sz;
    uint64_t           block_sz;
    merr_t             err;
    uint64_t          *samples;
};

struct mp_prof_stat {
    double latmean;
    double latsigma;
};

static double
score_prof_stat(struct mp_prof_stat *mp_ps)
{
    double mean_us = mp_ps->latmean / 1000.0;
    double sigma_us = mp_ps->latsigma / 1000.0;
    double sigma2mean = sigma_us / mean_us;

    if ((mean_us < 3000.0 && sigma2mean < 1.5) || (mean_us < 6000.0 && sigma2mean < 1.2))
        return 0.0;
    else if (
        (mean_us < 6000.0 && sigma2mean < 1.5) || (mean_us < 8000.0 && sigma2mean < 1.2) ||
        (mean_us < 10000.0 && sigma2mean < 1.0) || (mean_us < 12000.0 && sigma2mean < 0.7) ||
        (mean_us < 15000.0 && sigma2mean < 0.5))
        return 1.0;
    else
        return 2.0;
}

static void
sigint_handler(int signum)
{
    sigint = 1;
}

static void
sigalrm_handler(int signum)
{
    sigalrm = 1;
}

static int
sighandler_install(int signum, __sighandler_t func)
{
    struct sigaction act = {0};

    act.sa_handler = func;
    sigemptyset(&act.sa_mask);

    return sigaction(signum, &act, (struct sigaction *)0);
}

static void
mpool_cparams_init(const char *path, struct mpool_cparams *params)
{
    mpool_cparams_defaults(params);

    assert(path);
    strlcpy(params->mclass[MP_MED_CAPACITY].path, path,
            sizeof(params->mclass[MP_MED_CAPACITY].path));
}

static void
mpool_rparams_init(const char *path, struct mpool_rparams *params)
{
    assert(path);
    strlcpy(params->mclass[MP_MED_CAPACITY].path, path,
            sizeof(params->mclass[MP_MED_CAPACITY].path));
}

static void
mpool_dparams_init(const char *path, struct mpool_dparams *params)
{
    assert(path);
    strlcpy(params->mclass[MP_MED_CAPACITY].path, path,
            sizeof(params->mclass[MP_MED_CAPACITY].path));
}

static void
profile_worker(struct work_struct *arg)
{
    struct mp_profile_work *work;
    struct mpool           *mp;
    uint32_t                mblock_cnt;
    uint64_t                mblock_sz;
    uint64_t                block_sz;
    uint64_t               *samples;
    struct iovec            iov;
    void                   *buf;
    uint64_t                start, stop;
    struct mblock_props     mbprop;
    uint64_t                handle;
    merr_t                  err = 0;
    uint32_t                i, sample_idx;
    char                    errbuf[128];
    int                     block, num_blocks;

    work = container_of(arg, struct mp_profile_work, work_elem);

    buf = alloc_aligned(work->block_sz, PAGE_SIZE);
    if (!buf) {
        fprintf(stderr, "alloc_aligned() failed for %lu bytes, page aligned\n", work->block_sz);
        work->err = merr(ENOMEM);

        return;
    }

    mp = work->mp;
    mblock_cnt = work->mblock_cnt;
    mblock_sz = work->mblock_sz;
    block_sz = work->block_sz;
    samples = work->samples;

    sample_idx = 0;
    num_blocks = mblock_sz / block_sz;

    for (block = 0; block < mblock_cnt && !sigint && !sigalrm; ++block) {
        err = mpool_mblock_alloc(mp, MP_MED_CAPACITY, &handle, &mbprop);
        if (err) {
            work->err = err;
            merr_strerror(err, errbuf, sizeof(errbuf));
            fprintf(stderr, "Failed to allocate storage object: %s\n", errbuf);
            break;
        }

        for (i = 0; i < num_blocks && !sigint && !sigalrm; i++) {
            iov.iov_base = buf;
            iov.iov_len = block_sz;

            start = get_time_ns();

            err = mpool_mblock_write(mp, handle, &iov, 1);
            if (err) {
                work->err = err;
                merr_strerror(err, errbuf, sizeof(errbuf));
                fprintf(stderr, "Failed to write to storage object: %s\n", errbuf);
                break;
            }

            stop = get_time_ns();

            samples[sample_idx++] = stop - start;
        }

        err = mpool_mblock_abort(mp, handle);
        if (err) {
            work->err = work->err ? : err;
            merr_strerror(err, errbuf, sizeof(errbuf));
            fprintf(stderr, "Failed to reclaim storage space: %s\n", errbuf);
            break;
        }
    }

    if (sigint) {
        work->err = merr(EINTR);
        work->num_samples = 0;
    } else {
        work->num_samples = sample_idx;
    }

    free_aligned(buf);

    return;
}

static int
perform_profile_run(
    struct mpool *mp,
    uint32_t      thread_cnt,
    uint32_t      mblocks_per_thread,
    uint64_t      mblock_sz,
    uint64_t      block_sz,
    double       *score)
{
    struct workqueue_struct *workqueue;
    struct mp_profile_work  *work_specs;
    int                      i, j, rc = 0;
    const uint32_t           samples_per_thread = mblocks_per_thread * (mblock_sz / block_sz);
    struct mp_prof_stat      stats;
    uint64_t                 sum, tot_samples;
    double                   tmp, var_sum;
    double                   mean;
    double                   sigma;
    char                     errbuf[128];
    sigset_t                 blockset, origset;
    struct itimerval         timer = {0};

    sigemptyset(&blockset);
    sigaddset(&blockset, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &blockset, &origset);

    workqueue = alloc_workqueue("kvdb_profiling_wq", 0, thread_cnt);
    if (!workqueue)
        return ENOMEM;

    work_specs = malloc(thread_cnt * sizeof(struct mp_profile_work));
    if (!work_specs) {
        destroy_workqueue(workqueue);
        return ENOMEM;
    }

    /* prepare the per-thread data */
    for (i = 0; i < thread_cnt; ++i) {
        work_specs[i].mp = mp;
        work_specs[i].tid = i;
        work_specs[i].mblock_cnt = mblocks_per_thread;
        work_specs[i].mblock_sz = mblock_sz;
        work_specs[i].block_sz = block_sz;
        work_specs[i].err = 0;

        work_specs[i].samples = malloc(samples_per_thread * sizeof(double));
        if (!work_specs[i].samples) {
            rc = ENOMEM;
            thread_cnt = i;
            goto err_exit;
        }

        INIT_WORK(&work_specs[i].work_elem, profile_worker);
    }

    timer.it_value.tv_sec = test_time_secs;
    rc = setitimer(ITIMER_REAL, &timer, NULL);
    if (rc) {
        rc = errno;
        goto err_exit;
    }

    /* launch the threads */
    for (i = 0; i < thread_cnt; ++i)
        queue_work(workqueue, &work_specs[i].work_elem);

    pthread_sigmask(SIG_BLOCK, &origset, NULL);
    sighandler_install(SIGALRM, sigalrm_handler);

    /* wait for IO to complete or timeout */
    flush_workqueue(workqueue);

    /* process any errors that occurred */
    for (i = 0; i < thread_cnt; ++i) {
        if (work_specs[i].err) {
            rc = merr_errno(work_specs[i].err);
            if (rc != EINTR) {
                merr_strerror(work_specs[i].err, errbuf, sizeof(errbuf));
                fprintf(stderr, "Profile thread %d failed: %s\n", i, errbuf);
            }

            goto err_exit;
        }
    }

    /* process the results from the runs */
    sum = 0UL;
    tot_samples = 0;
    for (i = 0; i < thread_cnt; ++i) {
        for (j = 0; j < work_specs[i].num_samples; ++j)
            sum += work_specs[i].samples[j];
        tot_samples += work_specs[i].num_samples;
    }

    if (tot_samples == 0) {
        rc = EINTR;
        goto err_exit;
    }

    mean = (double)sum / (double)tot_samples;

    var_sum = 0.0;
    for (i = 0; i < thread_cnt; ++i) {
        for (j = 0; j < work_specs[i].num_samples; ++j) {
            tmp = (double)work_specs[i].samples[j] - mean;
            var_sum += tmp * tmp;
        }
    }
    sigma = sqrt(var_sum / (double)tot_samples);

    stats.latmean = mean;
    stats.latsigma = sigma;

    *score = score_prof_stat(&stats);

err_exit:
    for (i = 0; i < thread_cnt; ++i)
        free(work_specs[i].samples);

    free(work_specs);
    destroy_workqueue(workqueue);

    return rc;
}

static int
profile_mpool(const char *path, uint64_t mblock_sz, uint32_t thread_cnt, double *score)
{
    struct mpool *mp;
    struct mpool_rparams params = {0};

    merr_t        err;
    int           flags = O_RDWR;
    uint64_t      block_sz = MP_PROF_BLOCK_SIZE;
    uint32_t      mblocks_per_thread = MP_PROF_MBLOCKS_PER_THREAD;
    char          errbuf[128];
    int           rc;

    mpool_rparams_init(path, &params);

    err = mpool_open(path, &params, flags, &mp);
    if (err) {
        merr_strerror(err, errbuf, sizeof(errbuf));
        fprintf(stderr, "Failed to open storage %s: %s\n", path, errbuf);
        return merr_errno(err);
    }

    rc = perform_profile_run(mp, thread_cnt, mblocks_per_thread, mblock_sz, block_sz, score);

    mpool_close(mp);

    return rc;
}

static int
get_mpool_info(const char *path, struct mpool_info *info)
{
    merr_t                    err;
    struct mpool             *mp;
    int                       flags = O_RDWR;
    struct mpool_props        props;
    struct mpool_rparams      params = {0};
    struct mpool_mclass_stats mc_stats = {};
    char                      errbuf[128];

    mpool_rparams_init(path, &params);

    err = mpool_open(path, &params, flags, &mp);
    if (err) {
        merr_strerror(err, errbuf, sizeof(errbuf));
        fprintf(stderr, "Failed to open storage %s: %s\n", path, errbuf);
        return merr_errno(err);
    }

    err = mpool_props_get(mp, &props);
    if (err) {
        mpool_close(mp);
        merr_strerror(err, errbuf, sizeof(errbuf));
        fprintf(stderr, "Failed to fetch storage props for %s: %s\n", path, errbuf);
        return merr_errno(err);
    }

    err = mpool_mclass_stats_get(mp, MP_MED_CAPACITY, &mc_stats);
    if (err) {
        mpool_close(mp);
        merr_strerror(err, errbuf, sizeof(errbuf));
        fprintf(stderr, "Failed to fetch storage stats for %s: %s\n", path, errbuf);
        return merr_errno(err);
    }

    info->total_space = mc_stats.mcs_total;
    info->avail_space = mc_stats.mcs_available;
    info->mblock_sz = props.mp_mblocksz[MP_MED_CAPACITY] * MiB;

    mpool_close(mp);

    return 0;
}

static void
dump_usage(const char *program, bool verbose)
{
    printf("usage: %s [options] <storage_path>\n", program);

    printf(" -h\tprint this help list\n");
    printf(" -q\tquiet mode, outputs one of the following: [light, medium, default]\n");
    printf(" -v\tmake the profile output more explanatory\n");
    printf("\n");

    if (!verbose) {
        printf("Use -hv for more detail\n\n");
        return;
    }

    printf("This tool creates a temp directory called \"kvdb_profile.tmp\" in the user\n");
    printf("specified <storage_path>. On completion/exit, this temp directory and its\n");
    printf("contents are deleted.\n\n");
    printf("If the tool abruptly terminates, this temp directory is left behind.\n");
    printf("A subsequent run will automatically clean up the temp directory,\n");
    printf("otherwise this directory needs to be manually removed.\n\n");
    printf("Running concurrent instances of this tool is not supported.\n");
}

static int
handle_options(int argc, char *argv[], const char **path)
{
    const char  options[] = "hqv";
    const char *program;
    bool usage = false;

    program = strrchr(argv[0], '/');
    program = program ? program + 1 : argv[0];

    for (;;) {
        char c;

        c = getopt(argc, argv, options);
        if (-1 == c)
            break;

        switch (c) {
            case 'h':
                usage = true;
                break;

            case 'q':
                quiet = true;
                break;

            case 'v':
                verbose = true;
                break;
        }
    }

    if (usage) {
        dump_usage(program, verbose);
        exit(0);
    }

    argc -= optind;
    argv += optind;

    if (argc != 1) {
        fprintf(stderr, "Insufficient or extraneous arguments detected\n");
        dump_usage(program, false);
        return EX_USAGE;
    }

    *path = argv[0];

    return 0;
}

static int
profile_dir_destroy(const char *path)
{
    struct mpool_dparams dparams = {0};

    mpool_dparams_init(path, &dparams);

    mpool_destroy(path, &dparams);

    return rmdir(path);
}

int
main(int argc, char *argv[])
{
    struct mpool_cparams cparams = {0};
    struct mpool_info  info = {0};
    int                i, rc;
    int                thread_counts[] = { 16, 20, 24, 32, 40, 48 };
    int                num_thread_counts = NELEM(thread_counts);
    double             scores[num_thread_counts];
    double             avg_score;
    int                cnt_score;
    uint64_t           max_thrds = thread_counts[num_thread_counts - 1];
    uint64_t           mblock_sz;
    uint64_t           max_space_needed;
    const char        *result = "default";
    hse_err_t          herr;
    merr_t             err;
    char               errbuf[128];
    const char        *path;
    char               pathbuf[PATH_MAX];

    rc = handle_options(argc, argv, &path);
    if (rc)
        exit(EX_USAGE);

    herr = hse_init(NULL, 0, NULL);
    if (herr) {
        hse_strerror(herr, errbuf, sizeof(errbuf));
        fprintf(stderr, "Failed to initialize HSE: %s\n", errbuf);
        exit(EX_OSERR);
    }

    snprintf(pathbuf, sizeof(pathbuf), "%s/%s", path, MP_PROF_TMP_DIR);
    path = pathbuf;

    profile_dir_destroy(path); /* start with a clean profile dir */

    rc = mkdir(path, 0750);
    if (rc) {
        fprintf(stderr, "Failed to create profile directory: %s\n", strerror(errno));
        hse_fini();
        exit(EX_OSERR);
    }

    sighandler_install(SIGINT, sigint_handler);
    sighandler_install(SIGTERM, sigint_handler);
    sighandler_install(SIGHUP, sigint_handler);

    mpool_cparams_init(path, &cparams);

    err = mpool_create(path, &cparams);
    if (err) {
        merr_strerror(err, errbuf, sizeof(errbuf));
        fprintf(stderr, "Failed to initialize storage: %s\n", errbuf);
        rc = merr_errno(err);
        goto err_exit;
    }

    rc = get_mpool_info(path, &info);
    if (rc) {
        fprintf(stderr, "Failed to retrieve storage info: %s\n", strerror(rc));
        goto err_exit;
    }

    mblock_sz = info.mblock_sz;
    max_space_needed = max_thrds * MP_SPARE_MBLOCKS_PER_THREAD * mblock_sz;

    if (info.avail_space < max_space_needed) {
        uint32_t space_needed_mb = 1 + (max_space_needed / MiB);

        rc = ENOSPC;
        fprintf(
            stderr,
            "The profiling test needs %u MiB of free space to characterize KVDB performance.",
            space_needed_mb);

        goto err_exit;
    }

    for (i = 0; i < num_thread_counts; i++)
        scores[i] = NAN;

    if (!quiet)
        printf("Profiling in progress, will complete in 60 seconds...\n");

    for (i = 0; i < num_thread_counts && !sigint && !sigalrm; ++i) {
        rc = profile_mpool(path, mblock_sz, thread_counts[i], &scores[i]);
        if (rc) {
            fprintf(stderr, "Profiling failed: %s\n", strerror(rc));
            goto err_exit;
        }
    }

    if (sigint) {
        rc = EINTR;
        fprintf(stderr, "Profiling failed: %s\n", strerror(rc));
        goto err_exit;
    }

    avg_score = 0;
    cnt_score = 0;
    for (i = 0; i < num_thread_counts; ++i) {
        if (!isnan(scores[i])) {
            avg_score += scores[i];
            cnt_score++;
        }
    }

    if (cnt_score == 0) {
        rc = EBUG;
        fprintf(stderr, "Profiling failed: %s\n", strerror(rc));
        goto err_exit;
    }

    avg_score = avg_score / cnt_score;
    if (avg_score < 0.5)
        result = "light";
    else if (avg_score < 1.2)
        result = "medium";
    else
        result = "default";

    if (!quiet && !verbose)
        printf("\nRecommended throttle init policy: \"%s\"\n", result);
    else if (quiet)
        printf("%s\n", result);

err_exit:
    if (profile_dir_destroy(path))
        fprintf(stderr, "Failed to clean up profile dir %s, please remove manually\n", path);

    if (!verbose || rc) {
        hse_fini();
        return rc ? -1 : 0;
    }

    printf("\n");
    printf(
        "The performance profile suggests a setting of \"%s\" for the\n", result);
    printf("KVDB throttling.init_policy configuration parameter.\n");
    printf("\n");
    printf("If you are using the KVDB home config file ($kvdb_home/kvdb.conf),\n");
    printf("this would look like:\n");
    printf("\n");
    printf("{\"throttling.init_policy\": \"%s\"}\n", result);
    printf("\n");
    printf("along with whatever other configuration settings you already have.\n");
    printf("\n");
    printf("Running HSE with an improper setting for throttle.init_policy\n");
    printf("(e.g., \"medium\" for a slow KVDB storage device) will likely\n");
    printf("cause durability settings to not be honored and search data\n");
    printf("structures to become unbalanced until the throttling catches up.\n");

    hse_fini();

    return 0;
}
