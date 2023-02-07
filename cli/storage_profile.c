/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2020 Micron Technology, Inc.
 */

#include <sysexits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ftw.h>
#include <dirent.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <math.h>
#include <fcntl.h>
#include <time.h>

#include <sys/types.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#if __linux__
#include <linux/magic.h>
#endif

#include <hse/util/time.h>

/* We use 128KiB writes in all cases */
#define PROF_BLOCK_SIZE            (128u * 1024)
#define PROF_FILE_SIZE_PER_THREAD  (1ul << 30)

#define PAGE_SIZE                  (4096)

#define MIN_EXPECTED_LAT_NS        (1L)
#define MAX_EXPECTED_LAT_NS        (10L * 1000L * 1000L * 1000L)

#define PROF_TMP_DIR               "storage_profile.tmp"

static int test_time_secs = 60;
static sig_atomic_t sigint;
static sig_atomic_t sigalrm;

struct storage_info {
    uint64_t total_space;
    uint64_t avail_space;
};

struct storage_profile_work {
    int       dirfd;
    pthread_t tid;
    uint32_t  index;
    uint32_t  thrcnt;
    uint32_t  num_samples;
    uint64_t  file_sz;
    uint64_t  block_sz;
    int       rc;
    bool      tmpfs;
    uint64_t *samples;
};

struct storage_prof_stat {
    double latmean;
    double latsigma;
};

static double
score_prof_stat(struct storage_prof_stat *ps)
{
    double mean_us = ps->latmean / 1000.0;
    double sigma_us = ps->latsigma / 1000.0;
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

    return sigaction(signum, &act, NULL);
}

static uint64_t
get_time_ns(void)
{
    struct timespec ts = { 0, 0 };

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (uint64_t)(ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec);
}

static void*
profile_worker(void *rock)
{
    struct storage_profile_work *work;
    uint64_t  file_sz;
    uint64_t  block_sz;
    uint64_t *samples;
    void     *buf;
    uint64_t  start, stop;
    uint32_t  sample_idx;
    int       block, dirfd, fd, flags;
    uint64_t  num_blocks;
    char      fname[32];
    off_t     woff;
    char      errbuf[128];

    work = rock;

    pthread_setname_np(work->tid, "profile_worker");

    buf = aligned_alloc(PAGE_SIZE, work->block_sz);
    if (!buf) {
        work->rc = ENOMEM;
        fprintf(stderr, "aligned_alloc() failed for %lu bytes, page aligned\n", work->block_sz);
        goto out;
    }

    dirfd = work->dirfd;
    file_sz = work->file_sz;
    block_sz = work->block_sz;
    samples = work->samples;

    sample_idx = 0;
    num_blocks = file_sz / block_sz;

    snprintf(fname, sizeof(fname), "%s-%d-%d", "profile-file", work->thrcnt, work->index);

    flags = O_CREAT | O_EXCL | O_SYNC | O_RDWR;
    flags |= (work->tmpfs ? 0 : O_DIRECT);

    fd = openat(dirfd, fname, flags, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        work->rc = errno;
        fprintf(stderr, "Failed to create file %s: %s\n", fname,
                strerror_r(errno, errbuf, sizeof(errbuf)));
        goto out;
    }

    woff = 0;
    for (block = 0; block < num_blocks && !sigint && !sigalrm; ++block) {
        struct iovec iov;

        iov.iov_base = buf;
        iov.iov_len = block_sz;

        start = get_time_ns();

        while (iov.iov_len > 0 && !sigint && !sigalrm) {
            ssize_t cc;

            cc = pwritev(fd, &iov, 1, woff);
            if (cc == -1) {
                work->rc = errno;
                fprintf(stderr, "Failed to write to profile file %s: %s\n", fname,
                        strerror_r(errno, errbuf, sizeof(errbuf)));
                break;
            }

            woff += cc;
            iov.iov_base += cc;
            iov.iov_len -= (size_t)cc;
        }

        if (work->rc != 0)
            break;

        stop = get_time_ns();

        samples[sample_idx++] = stop - start;
    }

    if (sigint) {
        work->rc = EINTR;
        work->num_samples = 0;
    } else {
        work->num_samples = sample_idx;
    }

    close(fd);

out:
    free(buf);
    pthread_exit(NULL);
}

static int
perform_profile_run(
    int       dirfd,
    uint32_t  thread_cnt,
    uint64_t  file_sz,
    uint64_t  block_sz,
    double   *score)
{
    struct storage_profile_work *work_specs;
    struct storage_prof_stat stats;
    struct statfs sbuf;
    double tmp, var_sum, mean, sigma;
    uint64_t sum, tot_samples;
    const uint64_t samples_per_thread = (file_sz / block_sz);
    int j, rc = 0;
    bool tmpfs;
    sigset_t blockset, origset;

    sigemptyset(&blockset);
    sigaddset(&blockset, SIGALRM);
    sigaddset(&blockset, SIGINT);
    sigaddset(&blockset, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &blockset, &origset);

    work_specs = calloc(thread_cnt, sizeof(struct storage_profile_work));
    if (!work_specs)
        return ENOMEM;

    rc = fstatfs(dirfd, &sbuf);
    if (rc == -1) {
        rc = errno;
        goto err_exit;
    }
    tmpfs = (sbuf.f_type == TMPFS_MAGIC);

    /* prepare the per-thread data */
    for (uint32_t i = 0; i < thread_cnt; ++i) {
        work_specs[i].dirfd = dirfd;
        work_specs[i].index = i;
        work_specs[i].thrcnt = thread_cnt;
        work_specs[i].file_sz = file_sz;
        work_specs[i].block_sz = block_sz;
        work_specs[i].tmpfs = tmpfs;
        work_specs[i].rc = 0;

        work_specs[i].samples = malloc(samples_per_thread * sizeof(*work_specs[i].samples));
        if (!work_specs[i].samples) {
            rc = ENOMEM;
            thread_cnt = i;
            goto err_exit;
        }
    }

    /* launch the threads */
    for (uint32_t i = 0; i < thread_cnt; ++i) {
        rc = pthread_create(&work_specs[i].tid, NULL, profile_worker, &work_specs[i]);
        if (rc > 0) {
            while (i-- > 0) {
                pthread_kill(work_specs[i].tid, SIGINT);
                pthread_join(work_specs[i].tid, NULL);
            }

            goto err_exit;
        }
    }

    pthread_sigmask(SIG_SETMASK, &origset, NULL);

    /* wait for IO to complete or timeout */
    for (uint32_t i = 0; i < thread_cnt; ++i)
        pthread_join(work_specs[i].tid, NULL);

    /* process any errors that occurred */
    for (uint32_t i = 0; i < thread_cnt; ++i) {
        if (work_specs[i].rc) {
            rc = work_specs[i].rc;
            if (rc != EINTR)
                fprintf(stderr, "Profiling by thread index %d count %d failed: %s\n",
                        i, thread_cnt, strerror(rc));

            goto err_exit;
        }
    }

    /* process the results from the runs */
    sum = 0UL;
    tot_samples = 0;
    for (uint32_t i = 0; i < thread_cnt; ++i) {
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
    for (uint32_t i = 0; i < thread_cnt; ++i) {
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
    for (uint32_t i = 0; i < thread_cnt; ++i)
        free(work_specs[i].samples);

    free(work_specs);

    return rc;
}

static int
profile_storage(const char *path, uint32_t thread_cnt, double *score)
{
    uint64_t block_sz = PROF_BLOCK_SIZE;
    int      rc;

    DIR *dirp;

    dirp = opendir(path);
    if (!dirp) {
        fprintf(stderr, "Failed to open storage %s: %s\n", path, strerror(errno));
        return errno;
    }

    rc = perform_profile_run(dirfd(dirp), thread_cnt, PROF_FILE_SIZE_PER_THREAD, block_sz, score);

    closedir(dirp);

    return rc;
}

static int
get_storage_info(const char *path, struct storage_info *info)
{
    struct statvfs sbuf = {};
    int rc;

    rc = statvfs(path, &sbuf);
    if (rc == -1) {
        fprintf(stderr, "Failed to retrieve FS stats for %s: %s\n", path, strerror(errno));
        return errno;
    }

    info->total_space = sbuf.f_blocks * sbuf.f_frsize;
    info->avail_space = sbuf.f_bavail * sbuf.f_bsize;

    return 0;
}

static int
profile_file_remove(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    remove(path);

    return FTW_CONTINUE;
}

static void
profile_files_remove(const char *path)
{
    nftw(path, profile_file_remove, 64, FTW_PHYS | FTW_ACTIONRETVAL);
}

static int
profile_dir_remove(const char *path)
{
    int rc;

    profile_files_remove(path);

    rc = rmdir(path);
    if (rc == -1 && errno == ENOENT)
        rc = 0;

    return rc;
}

int
hse_storage_profile(const char *path, bool quiet, bool verbose)
{
    struct storage_info info = {0};
    struct itimerval timer = {0};
    const unsigned int thread_counts[] = { 16, 20, 24, 32, 40, 48 };
    const int num_thread_counts = sizeof(thread_counts) / sizeof(thread_counts[0]);
    double scores[num_thread_counts], avg_score;
    uint64_t max_thrds = thread_counts[num_thread_counts - 1];
    uint64_t max_space_needed;
    int i, rc, cnt_score;
    const char *result = "heavy";
    char pathbuf[PATH_MAX];

    snprintf(pathbuf, sizeof(pathbuf), "%s/%s", path, PROF_TMP_DIR);
    path = pathbuf;

    profile_dir_remove(path); /* start with a clean profile dir */

    rc = mkdir(path, 0750);
    if (rc == -1) {
        fprintf(stderr, "Failed to create profile directory: %s\n", strerror(errno));
        return errno;
    }

    sighandler_install(SIGINT, sigint_handler);
    sighandler_install(SIGTERM, sigint_handler);
    sighandler_install(SIGHUP, sigint_handler);
    sighandler_install(SIGALRM, sigalrm_handler);

    rc = get_storage_info(path, &info);
    if (rc) {
        fprintf(stderr, "Failed to retrieve storage info: %s\n", strerror(rc));
        goto err_exit;
    }

    max_space_needed = max_thrds * PROF_FILE_SIZE_PER_THREAD;

    if (info.avail_space < max_space_needed) {
        const uint64_t space_needed_mb = 1 + (max_space_needed / (1u << 20));

        rc = ENOSPC;
        /* This output message is grepped by
         * tests/function/cli/storage/profile/success.sh
         */
        fprintf(
            stderr,
            "The profiling test needs %lu MiB of free space to characterize KVDB performance.\n",
            space_needed_mb);

        goto err_exit;
    }

    for (i = 0; i < num_thread_counts; i++)
        scores[i] = NAN;

    timer.it_value.tv_sec = test_time_secs;
    rc = setitimer(ITIMER_REAL, &timer, NULL);
    if (rc) {
        fprintf(stderr, "Profiling failed, unable to arm internal timer: %s\n", strerror(rc));
        goto err_exit;
    }

    if (!quiet)
        printf("Profiling in progress, will complete in 60 seconds...\n");

    for (i = 0; i < num_thread_counts && !sigint && !sigalrm; ++i) {
        rc = profile_storage(path, thread_counts[i], &scores[i]);
        if (rc) {
            fprintf(stderr, "Profiling failed: %s\n", strerror(rc));
            goto err_exit;
        }

        profile_files_remove(path);
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
        rc = EX_SOFTWARE;
        fprintf(stderr, "Profiling failed: %s\n", strerror(rc));
        goto err_exit;
    }

    avg_score = avg_score / cnt_score;
    if (avg_score < 0.5)
        result = "light";
    else if (avg_score < 1.2)
        result = "medium";
    else
        result = "heavy";

    if (!quiet && !verbose)
        printf("\nRecommended throttling.init_policy: \"%s\"\n", result);
    else if (quiet)
        printf("%s\n", result);

err_exit:
    if (profile_dir_remove(path))
        fprintf(stderr, "Failed to clean up profile dir %s, please remove manually\n", path);

    if (!verbose || rc)
        return rc ? -1 : 0;

    printf("\n");
    printf(
        "The performance profile suggests a setting of \"%s\" for the\n", result);
    printf("KVDB throttling.init_policy configuration parameter.\n");
    printf("\n");
    printf("If you are using the KVDB home config file ($kvdb_home/kvdb.conf),\n");
    printf("this would look like:\n");
    printf("\n");
    printf("{\"throttling\": {\"init_policy\": \"%s\"}}\n", result);
    printf("\n");
    printf("along with whatever other configuration settings you already have.\n");
    printf("\n");
    printf("Running HSE with an improper setting for throttling.init_policy\n");
    printf("(e.g., \"medium\" for a slow KVDB storage device) will likely\n");
    printf("cause durability settings to not be honored and search data\n");
    printf("structures to become unbalanced until the throttling catches up.\n");

    return 0;
}
