/*
 * Copyright (C) 2020 Micron Technology, Inc. All rights reserved.
 */

#include <mpool/mpool.h>
#if HDR_HISTOGRAM_C_FROM_SUBPROJECT == 1
#include <hdr_histogram.h>
#else
#include <hdr/hdr_histogram.h>
#endif

#include <hse_util/alloc.h>
#include <hse_util/page.h>
#include <hse_util/inttypes.h>
#include <hse_util/log2.h>
#include <hse_util/timing.h>
#include <hse_util/workqueue.h>

#include "deviceprofile.h"

struct deviceprofile_calibrate_elem {
    struct hdr_histogram *dp_histogram;
    u32                   dp_bsize;
    u64                   dp_ops;
};

struct deviceprofile_calibrate;

struct deviceprofile_calibrate_work {
    struct work_struct                  dp_work;
    hse_err_t                              dp_err;
    int                                 dp_tid;
    struct deviceprofile_calibrate *    dp_calibrate;
    struct deviceprofile_calibrate_elem dp_elem;
    u64                                 dp_min;
    u64                                 dp_max;
};

struct deviceprofile_calibrate {
    struct mpool *                       dp_ds;
    enum mpool_mclass                    dp_mclass;
    int                                  dp_threads;
    u32                                  dp_mblksize;
    u64                                  dp_samplesize;
    struct workqueue_struct *            dp_workqueue;
    struct deviceprofile_calibrate_work *dp_elem_work;
};

#define HDR_INIT_SZ (60UL * 1000UL * 1000UL * 1000UL)

void
deviceprofile_calibrate_worker(struct work_struct *arg)
{
    struct deviceprofile_calibrate_work *work;
    struct mblock_props                  mbprop;
    u64                                  handle, samplesize;
    u64                                  blocksize, mblksize;
    u64                                  ops = 0, ns1, ns2;
    hse_err_t                               err = 0, err2;
    struct iovec                         iov;
    void *                               buf;
    int                                  i;
    int                                  block, num_blocks;

    work = container_of(arg, struct deviceprofile_calibrate_work, dp_work);

    blocksize = work->dp_elem.dp_bsize;
    mblksize = work->dp_calibrate->dp_mblksize;
    samplesize = work->dp_calibrate->dp_samplesize;

    /* enforce that samplesize == k*mblksize for some positive integer k */
    if ((samplesize % mblksize) != 0) {
        fprintf(stderr, "sample size (%ld) must be a multiple of mblock size (%ld)\n",
                samplesize, mblksize);
        return;
    }

    /* iterate over this many mblocks to reach samplesize */
    num_blocks = samplesize / mblksize;

    buf = alloc_aligned(PAGE_SIZE, blocksize);
    if (!buf) {
        fprintf(stderr, "alloc_aligned() failed for %ld bytes, page aligned\n", blocksize);
        work->dp_err = ENOMEM;
        return;
    }

    work->dp_elem.dp_ops = 0;
    work->dp_err = 0;

    work->dp_min = 0xffffffffffffffffUL;
    work->dp_max = 0x0UL;

    ns1 = get_time_ns();

    for (block = 0; block < num_blocks; ++block) {
        err = mpool_mblock_alloc(
            work->dp_calibrate->dp_ds, work->dp_calibrate->dp_mclass, &handle, &mbprop);
        if (err) {
            struct merr_info info;

            fprintf(stderr, "mpool_mblock_alloc() failed: %s\n",
                    merr_info(err, &info));
            work->dp_err = err;
            break;
        }

        for (i = 0; i < (mblksize / blocksize); i++) {
            iov.iov_base = buf;
            iov.iov_len = blocksize;

            ns2 = get_time_ns();

            err = mpool_mblock_write(work->dp_calibrate->dp_ds, handle, &iov, 1);
            if (err) {
                struct merr_info info;

                fprintf(stderr, "mpool_mblock_write() failed: %s\n",
                        merr_info(err, &info));
                work->dp_err = err;
                break;
            }

            ns2 = get_time_ns() - ns2;
            ops++;
            hdr_record_value(work->dp_elem.dp_histogram, ns2);
            if (ns2 < work->dp_min)
              work->dp_min = ns2;
            if (ns2 > work->dp_max)
              work->dp_max = ns2;
        }

        err2 = mpool_mblock_abort(work->dp_calibrate->dp_ds, handle);
        if (err2) {
            struct merr_info info;

            fprintf(stderr, "mpool_mblock_write() failed: %s\n",
                    merr_info(err2, &info));
            work->dp_err = (err == 0) ? err2 : err;
            break;
        }

        if (err)
            break;
    }

    free(buf);

    if (err)
        return;

    if (!ops) {
        fprintf(stderr, "ops == NULL\n");
        work->dp_err = EINVAL;
        return;
    }

    ns1 = get_time_ns() - ns1;
    work->dp_elem.dp_ops = (ops * NSEC_PER_SEC) / ns1;
}

hse_err_t
deviceprofile_calibrate_sample(
    struct deviceprofile_calibrate *deviceprofile,
    int                             write_pct,
    u32                             bsize,
    struct deviceprofile_stat *     read,
    struct deviceprofile_stat *     write)
{
    struct hdr_histogram *histogram;
    int                   idx, i;

    idx = ilog2(bsize);
    if (idx < DEVICEPROFILE_MINIDX || idx >= DEVICEPROFILE_MAXIDX)
        return EINVAL;

    for (i = 0; i < deviceprofile->dp_threads; i++) {
        struct deviceprofile_calibrate_work *work;

        work = &deviceprofile->dp_elem_work[i];

        work->dp_elem.dp_bsize = bsize;
        work->dp_elem.dp_ops = 0;
        work->dp_err = 0;
        work->dp_tid = i;
        work->dp_calibrate = deviceprofile;

        INIT_WORK(&work->dp_work, deviceprofile_calibrate_worker);
        queue_work(deviceprofile->dp_workqueue, &work->dp_work);
    }

    flush_workqueue(deviceprofile->dp_workqueue);

    write->dp_ops = 0;

    for (i = 0; i < deviceprofile->dp_threads; i++) {
        if (deviceprofile->dp_elem_work[i].dp_err)
            return deviceprofile->dp_elem_work[i].dp_err;

        write->dp_ops += deviceprofile->dp_elem_work[i].dp_elem.dp_ops;
    }

    hdr_init(1, HDR_INIT_SZ, 3, &histogram);
    for (i = 0; i < deviceprofile->dp_threads; i++)
        hdr_add(histogram, deviceprofile->dp_elem_work[i].dp_elem.dp_histogram);

    write->dp_latmin      = hdr_mean(histogram);
    write->dp_latmax      = hdr_max(histogram);
    write->dp_latmean     = hdr_mean(histogram);
    write->dp_latsigma    = hdr_stddev(histogram);
    write->dp_lat90pctle  = hdr_value_at_percentile(histogram, 90.0);
    write->dp_lat95pctle  = hdr_value_at_percentile(histogram, 95.0);
    write->dp_lat99pctle  = hdr_value_at_percentile(histogram, 99.0);
    write->dp_lat999pctle = hdr_value_at_percentile(histogram, 99.9);

    write->dp_trulatmin = 0xffffffffffffffffUL;
    write->dp_trulatmax = 0x0UL;
    for (i = 0; i < deviceprofile->dp_threads; i++) {
        if (deviceprofile->dp_elem_work[i].dp_min < write->dp_trulatmin)
          write->dp_trulatmin = deviceprofile->dp_elem_work[i].dp_min;

        if (deviceprofile->dp_elem_work[i].dp_max > write->dp_trulatmax)
          write->dp_trulatmax = deviceprofile->dp_elem_work[i].dp_max;
    }

    memset(read, 0, sizeof(*read));
    hdr_close(histogram);

    return 0;
}

hse_err_t
deviceprofile_calibrate_create(
    struct mpool *                   ds,
    enum mpool_mclass                mclass,
    u32                              mblk_size,
    u32                              mblks_per_thread,
    int                              threads,
    struct deviceprofile_calibrate **deviceprofileout)
{
    struct deviceprofile_calibrate *dprofile;
    int                             i;

    dprofile = malloc(sizeof(*dprofile));
    if (!dprofile)
        return ENOMEM;

    dprofile->dp_ds = ds;
    dprofile->dp_mclass = mclass;
    dprofile->dp_samplesize = (u64)mblks_per_thread * (u64)mblk_size;
    dprofile->dp_mblksize = mblk_size;
    dprofile->dp_threads = threads;
    dprofile->dp_elem_work = malloc(threads * sizeof(*dprofile->dp_elem_work));
    if (!dprofile->dp_elem_work) {
        free(dprofile);
        return ENOMEM;
    }

    memset(dprofile->dp_elem_work, 0, threads * sizeof(*dprofile->dp_elem_work));

    dprofile->dp_workqueue = alloc_workqueue("dp_workqueue", 0, threads);
    if (!dprofile->dp_workqueue) {
        free(dprofile->dp_elem_work);
        free(dprofile);
        return ENOMEM;
    }

    for (i = 0; i < threads; i++)
        hdr_init(1, HDR_INIT_SZ, 3, &dprofile->dp_elem_work[i].dp_elem.dp_histogram);

    *deviceprofileout = dprofile;

    return 0;
}

void
deviceprofile_calibrate_destroy(struct deviceprofile_calibrate *deviceprofile)
{
    int i;

    destroy_workqueue(deviceprofile->dp_workqueue);

    for (i = 0; i < deviceprofile->dp_threads; i++)
        hdr_close(deviceprofile->dp_elem_work[i].dp_elem.dp_histogram);

    free(deviceprofile->dp_elem_work);
    free(deviceprofile);
}
