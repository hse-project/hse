/*
 * Copyright (C) 2020 Micron Technology, Inc. All rights reserved.
 */

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <sysexits.h>

#include <mpool/mpool.h>

#include <hse/hse.h>

#include <hse_util/inttypes.h>

#include "deviceprofile.h"

static const char options[] = "m:b:s:t:c:w:";

static void
usage(const char *program)
{
    printf("usage: %s -s <sample size> [options] <mpool name>\n", program);

    printf("usage: %s -h\n", program);
    printf("-t number of I/O threads, default is 1\n");
    printf("-c media class, default is CAPACITY\n");
    printf("-b Per-io block size in KB in the range (%u .. %u), "
           "default is %u\n",
           DEVICEPROFILE_MINBSIZE / (1 << 10),
           DEVICEPROFILE_MAXBSIZE / (1 << 10),
           1 << 10);
    printf("-s # of mblocks per thread to sample (optional, defaults to 1).\n");
    printf("\n\nEXAMPLES:\n");
    printf("%s -s 8192 mp1\n", program);
    printf("%s -j 8 -c 6 -i 7 -b 128 -s 16384 mp1\n", program);
    printf("%s -j 128 -b 128 -s 65536 mp1\n", program);
}

#define MB (1024UL * 1024UL)

static void
output_result_int(struct deviceprofile_stat *stat, bool write)
{
    printf(
        "%-10s %10s %10s %10s %10s %10s %10s %10s %10s %10s %10s %10s\n",
        "OP",
        "ops",
        "TRUMIN_ns",
        "TRUMAX_ns",
        "MIN_ns",
        "MAX_ns",
        "MEAN_ns",
        "SIGMA_ns",
        "L90_ns",
        "L95_ns",
        "L99_ns",
        "L99.9_ns");

    printf("%-5s\t%10lu\t%10lu\t%10lu\t%10lu\t%10lu\t%10.1f\t%10.1f\t%10lu\t%10lu\t%10lu\t%10lu\n",
           (write) ? "WRITE" : "READ",
           stat->dp_ops,
           stat->dp_trulatmin,
           stat->dp_trulatmax,
           stat->dp_latmin,
           stat->dp_latmax,
           stat->dp_latmean,
           stat->dp_latsigma,
           stat->dp_lat90pctle,
           stat->dp_lat95pctle,
           stat->dp_lat99pctle,
           stat->dp_lat999pctle);
}

static void
output_result(struct deviceprofile_stat *rd, struct deviceprofile_stat *wr)
{
    if (wr->dp_ops)
        output_result_int(wr, true);
    if (rd->dp_ops)
        output_result_int(rd, false);
}

int
main(int argc, char *argv[])
{
    struct deviceprofile_calibrate *dpc;
    hse_err_t                       err;
    struct deviceprofile_stat       rd, wr;
    struct mpool *                  ds;
    int                             flags = O_RDWR;
    const char *                    program, *mpname;
    int                             mclass, wpct, thrds;
    u64                             bsize, mblks_per_thrd, mblksize;
    struct mpool_props              props;

    program = strrchr(argv[0], '/');
    program = program ? program + 1 : argv[0];
    mpname = NULL;

    mblks_per_thrd = 1;
    bsize = 1 << 20;
    wpct = 100;
    thrds = 1;
    mblksize = 1 << 25;
    mclass = MP_MED_CAPACITY;

    if (argc < 3) {
        usage(program);
        return -1;
    }

    err = hse_init();
    if (err)
        return -1;

    for (;;) {
        char c, *end;

        c = getopt(argc, argv, options);
        if (-1 == c)
            break;

        switch (c) {
            case 'h':
                usage(program);
                return 0;
            case 't':
                thrds = (int)strtoul(optarg, &end, 0);
                break;
            case 'c':
                mclass = (int)strtoul(optarg, &end, 0);
                if ((mclass < MP_MED_BASE) || (mclass >= MP_MED_COUNT)) {
                    usage(program);
                    return -1;
                }
                break;
            case 'b':
                bsize = strtoul(optarg, &end, 0);
                bsize *= 1024;
                if ((bsize < DEVICEPROFILE_MINBSIZE) || (bsize > DEVICEPROFILE_MAXBSIZE)) {
                    usage(program);
                    return -1;
                }
                break;
            case 's':
                mblks_per_thrd = strtoul(optarg, &end, 0);
                break;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc != 1) {
        fprintf(stderr, "Invalid or extraneous arguments\n");
        usage(program);
        err = EX_USAGE;
        goto err_exit;
    }

    if (mblks_per_thrd == 0) {
        usage(program);
        err = EX_USAGE;
        goto err_exit;
    }

    mpname = argv[0];

    if (!bsize || !mpname) {
        usage(program);
        err = EX_USAGE;
        goto err_exit;
    }

    err = mpool_open(mpname, NULL, flags, &ds);
    if (err) {
        fprintf(stderr, "mpool_open error %ld\n", err);
        goto err_exit;
    }

    err = mpool_props_get(ds, &props);
    if (err) {
        mpool_close(ds);
        fprintf(stderr, "mpool_props_get error %ld\n", err);
        goto err_exit;
    }

    mblksize = props.mp_mblocksz[mclass] * MB;
    err = deviceprofile_calibrate_create(ds, mclass, mblksize, mblks_per_thrd, thrds, &dpc);
    if (err) {
        fprintf(stderr, "Initialization error %ld\n", err);
        mpool_close(ds);
        goto err_exit;
    }

    err = deviceprofile_calibrate_sample(dpc, wpct, bsize, &rd, &wr);
    if (err)
        fprintf(stderr, "Sampling error %ld\n", err);
    else
        output_result(&rd, &wr);

    deviceprofile_calibrate_destroy(dpc);

    mpool_close(ds);

err_exit:
    hse_fini();

    return err;
}
