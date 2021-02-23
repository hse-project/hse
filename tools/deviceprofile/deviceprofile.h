/*
 * Copyright (C) 2020 Micron Technology, Inc. All rights reserved.
 */
#ifndef HSE_DEVICEPROFILE_H
#define HSE_DEVICEPROFILE_H

#include <hse/hse.h>
#include <mpool/mpool.h>

#include <hse_util/inttypes.h>

#define DEVICEPROFILE_MINIDX   10
#define DEVICEPROFILE_MAXIDX   25
#define DEVICEPROFILE_MINBSIZE (1 << DEVICEPROFILE_MINIDX)
#define DEVICEPROFILE_MAXBSIZE (1 << DEVICEPROFILE_MAXIDX)

struct deviceprofile_calibrate;

struct deviceprofile_stat {
    u64    dp_latmin;
    u64    dp_latmax;
    u64    dp_trulatmin;
    u64    dp_trulatmax;
    double dp_latmean;
    double dp_latsigma;
    u64    dp_lat90pctle;
    u64    dp_lat95pctle;
    u64    dp_lat99pctle;
    u64    dp_lat999pctle;
    u64    dp_ops;
};

hse_err_t
deviceprofile_calibrate_create(
    struct mpool *                   ds,
    enum mp_media_classp             mclass,
    u32                              mblk_size,
    u32                              sample_size,
    int                              threads,
    struct deviceprofile_calibrate **deviceprofileout);

void
deviceprofile_calibrate_destroy(struct deviceprofile_calibrate *deviceprofile);

hse_err_t
deviceprofile_calibrate_sample(
    struct deviceprofile_calibrate *deviceprofile,
    int                             write_pct,
    u32                             bsize,
    struct deviceprofile_stat *     read,
    struct deviceprofile_stat *     write);
#endif
