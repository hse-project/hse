// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/**
 * This file implements tests that are to be run in the mpft (MPool
 * Functional Test) framework.
 *
 * Available tests:
 * * perf_seq_writes - test performance of mlog writes
 *   - required parameters:
 *     - mpool (mp)
 *   - options:
 *     - record size (rs), default: 32B
 *     - total size (ts), default: all available space in mpool
 *     - thread count (threads), default: 1
 *     - sync, default: false
 *     - verify, default: false
 *     - pattern, default: 0x0123456789abcdef
 *
 *     Description: In the specified mpool create an MDC
 *       and then write records of size <rs> until <ts> bytes have been
 *       written.
 *
 *       If total size (ts) is not given on the command line, the amount
 *       of space available in the mpool is determined and used for total space.
 *
 *       The number of writes is determined by dividing total space by the
 *       record size. The writes will be evenly distributed across the
 *       specified number of threads.
 *
 *       If verify is set to true, then, after the performance measurement,
 *       the data written to the mlog will be read back and compared to the
 *       expected pattern. A custom pattern can be specified by the
 *       <pattern> parameter:
 *
 *       e.g: #./mpft mlog.perf.seq_writes mp=mp1 ts=1M
 *                  rs=1K pattern=0123456789abcdef verify=true
 *
 *       This command line will result in 1024 records of 1024B being
 *       written. The writes will have the pattern '0x0123456789abcdef'
 *       and the contents will be verified at the end of the run.
 *
 * * perf_seq_reads
 *   - parameters and options are the same as for perf_seq_writes
 *
 *     Description: perf_seq_reads follows the same steps as perf_seq_writes,
 *       but adds a loop reading back all of the records.
 */

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <getopt.h>

#include <hse_util/hse_err.h>
#include <hse_util/platform.h>
#include <hse_util/parse_num.h>
#include <hse_util/hse_params_helper.h>

#include <hse/hse.h>
#include <mpool/mpool.h>

#include "common.h"
#include "thread.h"

struct oid_pair {
    u64 oid[2];
};

static struct options {
    uint64_t recsz;
    uint64_t cap;
    uint16_t threads;
    uint16_t mode;
    bool     verify;
    bool     sync;
    bool     help;
} opt;

const char *progname = NULL;

#define MIN_SECTOR_SIZE  512
#define SECTOR_OVERHEAD  0
#define RECORD_OVERHEAD  12
#define LOG_OVERHEAD     4096
#define USABLE_SECT_SIZE (MIN_SECTOR_SIZE - SECTOR_OVERHEAD - RECORD_OVERHEAD)

#define MAX_PATTERN_SIZE 256

static u32
calc_record_count(u64 total_size, u32 record_size)
{
    u32 sector_cnt = total_size / MIN_SECTOR_SIZE;
    u32 sector_overhead = sector_cnt * SECTOR_OVERHEAD;
    u32 real_record_size;
    u32 record_cnt;
    u32 record_overhead;

    if (record_size < USABLE_SECT_SIZE)
        /* worst case a record can span two sectors */
        record_overhead = 2 * RECORD_OVERHEAD;
    else if (record_size > USABLE_SECT_SIZE)
        /* 2 here implies 1 leading + 1 trailing record desc. */
        record_overhead = ((record_size / USABLE_SECT_SIZE) + 2) * RECORD_OVERHEAD;
    else
        record_overhead = RECORD_OVERHEAD;

    real_record_size = record_size + record_overhead;
    record_cnt = (total_size - sector_overhead - LOG_OVERHEAD) / real_record_size;

    return record_cnt;
}

static unsigned int mclass = MP_MED_CAPACITY;

struct ml_writer_args {
    struct mpool *  mp;
    u32             rs; /* write size in bytes */
    u32             wc; /* write count */
    struct oid_pair oid;
};

struct ml_writer_resp {
    merr_t err;
    u32    usec;
    u64    bytes_written;
};

static void *
ml_writer(void *arg)
{
    merr_t err;
    int    i;
    char * buf;
    u32    usec;
    char   err_str[256];
    long   written = 0;

    struct thread_args *   targs = (struct thread_args *)arg;
    struct ml_writer_args *args = (struct ml_writer_args *)targs->arg;
    struct ml_writer_resp *resp;
    struct mpool_mdc *     mdc;
    struct timeval         start_tv, stop_tv;
    int                    id = targs->instance;
    size_t                 used;
    u64                    oid1 = args->oid.oid[0];
    u64                    oid2 = args->oid.oid[1];
    u32                    write_cnt = args->wc;
    u32                    write_sz = args->rs;

    resp = calloc(1, sizeof(*resp));
    if (!resp) {
        err = merr(ENOMEM);
        fprintf(
            stderr,
            "[%d]%s: Unable to allocate response struct:%s\n",
            id,
            __func__,
            merr_strinfo(err, err_str, sizeof(err_str), NULL));
        return resp;
    }

    err = mpool_mdc_open(args->mp, oid1, oid2, &mdc);
    if (err) {
        fprintf(
            stderr,
            "[%d]%s: Unable to open mdc: %s\n",
            id,
            __func__,
            merr_strinfo(err, err_str, sizeof(err_str), NULL));
        resp->err = err;
        return resp;
    }

    buf = calloc(1, write_sz);
    if (!buf) {
        err = resp->err = merr(ENOMEM);
        fprintf(
            stderr,
            "[%d]%s: Unable to allocate buf: %s\n",
            id,
            __func__,
            merr_strinfo(err, err_str, sizeof(err_str), NULL));
        goto close_mdc;
    }
    pattern_fill(buf, write_sz);

    thread_wait_for_start(targs);

    /* start timer */
    gettimeofday(&start_tv, NULL);

    for (i = 0; i < write_cnt - 1; i++) {
        err = mpool_mdc_append(mdc, buf, write_sz, opt.sync);
        if (err) {
            fprintf(
                stderr,
                "[%d]%s: error on async append #%d bytes "
                "written %ld: %s\n",
                id,
                __func__,
                i,
                written,
                merr_strinfo(err, err_str, sizeof(err_str), NULL));
            resp->err = err;
            goto free_buf;
        }
        written += write_sz;
    }

    err = mpool_mdc_append(mdc, buf, write_sz, true); /*  sync */
    if (err) {
        fprintf(
            stderr,
            "[%d]%s: error on append: %s\n",
            id,
            __func__,
            merr_strinfo(err, err_str, sizeof(err_str), NULL));
        resp->err = err;
        goto free_buf;
    }

    err = mpool_mdc_usage(mdc, &used);
    if (err) {
        fprintf(
            stderr,
            "[%d]%s: Unable to get mdc usage: %s\n",
            id,
            __func__,
            merr_strinfo(err, err_str, sizeof(err_str), NULL));
        resp->err = err;
        goto free_buf;
    }

    /* end timer */
    gettimeofday(&stop_tv, NULL);

    if (stop_tv.tv_usec < start_tv.tv_usec) {
        stop_tv.tv_sec--;
        stop_tv.tv_usec += 1000000;
    }
    usec = (stop_tv.tv_sec - start_tv.tv_sec) * 1000000 + (stop_tv.tv_usec - start_tv.tv_usec);

    resp->usec = usec;
    resp->bytes_written = used;

free_buf:
    free(buf);
close_mdc:
    (void)mpool_mdc_close(mdc);
    return resp;
}

struct ml_reader_args {
    struct mpool *  mp;
    u32             rs; /* read size in bytes */
    u32             rc; /* read count */
    struct oid_pair oid;
};

struct ml_reader_resp {
    merr_t err;
    u32    usec;
    u64    read;
};

static void *
ml_reader(void *arg)
{
    merr_t err;
    int    i;
    char * buf;
    u32    usec;
    char   err_str[256];
    size_t bytes_read = 0;

    struct thread_args *   targs = (struct thread_args *)arg;
    struct ml_reader_args *args = (struct ml_reader_args *)targs->arg;
    struct ml_reader_resp *resp;
    struct mpool_mdc *     mdc;
    struct timeval         start_tv, stop_tv;
    int                    id = targs->instance;
    size_t                 used;
    u64                    oid1 = args->oid.oid[0];
    u64                    oid2 = args->oid.oid[1];
    u32                    read_cnt = args->rc;

    resp = calloc(1, sizeof(*resp));
    if (!resp) {
        err = merr(ENOMEM);
        fprintf(
            stderr,
            "[%d]%s: Unable to allocate response struct:%s\n",
            id,
            __func__,
            merr_strinfo(err, err_str, sizeof(err_str), NULL));
        return resp;
    }

    err = mpool_mdc_open(args->mp, oid1, oid2, &mdc);
    if (err) {
        fprintf(
            stderr,
            "[%d]%s: Unable to open mdc: %s\n",
            id,
            __func__,
            merr_strinfo(err, err_str, sizeof(err_str), NULL));
        resp->err = err;
        return resp;
    }

    err = mpool_mdc_rewind(mdc);
    if (err) {
        fprintf(stderr, "[%d]%s: Unable to rewind\n", id, __func__);
        resp->err = err;
        return resp;
    }

    err = mpool_mdc_usage(mdc, &used);
    if (err) {
        fprintf(
            stderr,
            "[%d]%s: Unable to get mdc usage: %s\n",
            id,
            __func__,
            merr_strinfo(err, err_str, sizeof(err_str), NULL));
        resp->err = err;
        return resp;
    }

    buf = calloc(1, args->rs);
    if (!buf) {
        err = resp->err = merr(ENOMEM);
        fprintf(
            stderr,
            "[%d]%s: Unable to allocate buf: %s\n",
            id,
            __func__,
            merr_strinfo(err, err_str, sizeof(err_str), NULL));
        return resp;
    }

    thread_wait_for_start(targs);

    /* start timer */
    gettimeofday(&start_tv, NULL);

    for (i = 0; i < read_cnt; i++) {
        err = mpool_mdc_read(mdc, buf, args->rs, &bytes_read);
        if (err) {
            fprintf(
                stderr,
                "[%d]%s: error on read:%s\n",
                i,
                __func__,
                merr_strinfo(err, err_str, sizeof(err_str), NULL));
            resp->err = err;
            return resp;
        }
    }

    /* end timer */
    gettimeofday(&stop_tv, NULL);

    if (stop_tv.tv_usec < start_tv.tv_usec) {
        stop_tv.tv_sec--;
        stop_tv.tv_usec += 1000000;
    }
    usec = (stop_tv.tv_sec - start_tv.tv_sec) * 1000000 + (stop_tv.tv_usec - start_tv.tv_usec);

    resp->usec = usec;
    resp->read = used;

    mpool_mdc_close(mdc);
    free(buf);

    return resp;
}

struct ml_verify_args {
    struct mpool *  mp;
    u32             rs; /* read size in bytes */
    u32             rc; /* read count */
    struct oid_pair oid;
};

struct ml_verify_resp {
    merr_t err;
    u32    usec;
    u64    verified;
};

static void *
ml_verify(void *arg)
{
    merr_t err;
    int    i;
    char * buf;
    u32    usec;
    char   err_str[256];
    size_t bytes_read = 0;
    int    ret;

    struct thread_args *   targs = (struct thread_args *)arg;
    struct ml_verify_args *args = (struct ml_verify_args *)targs->arg;
    struct ml_verify_resp *resp;
    struct mpool_mdc *     mdc;
    struct timeval         start_tv, stop_tv;
    int                    id = targs->instance;
    size_t                 used;
    u64                    oid1 = args->oid.oid[0];
    u64                    oid2 = args->oid.oid[1];
    u32                    read_cnt = args->rc;

    resp = calloc(1, sizeof(*resp));
    if (!resp) {
        err = merr(ENOMEM);
        fprintf(
            stderr,
            "[%d]%s: Unable to allocate response struct:%s\n",
            id,
            __func__,
            merr_strinfo(err, err_str, sizeof(err_str), NULL));
        return resp;
    }

    err = mpool_mdc_open(args->mp, oid1, oid2, &mdc);
    if (err) {
        fprintf(
            stderr,
            "[%d]%s: Unable to open mdc: %s\n",
            id,
            __func__,
            merr_strinfo(err, err_str, sizeof(err_str), NULL));
        resp->err = err;
        return resp;
    }

    err = mpool_mdc_rewind(mdc);
    if (err) {
        fprintf(stderr, "[%d]%s: Unable to rewind\n", id, __func__);
        resp->err = err;
        return resp;
    }

    err = mpool_mdc_usage(mdc, &used);
    if (err) {
        fprintf(
            stderr,
            "[%d]%s: Unable to get mdc usage: %s\n",
            id,
            __func__,
            merr_strinfo(err, err_str, sizeof(err_str), NULL));
        resp->err = err;
        return resp;
    }

    buf = calloc(1, args->rs);
    if (!buf) {
        err = resp->err = merr(ENOMEM);
        fprintf(
            stderr,
            "[%d]%s: Unable to allocate buf: %s\n",
            id,
            __func__,
            merr_strinfo(err, err_str, sizeof(err_str), NULL));
        return resp;
    }

    thread_wait_for_start(targs);

    /* start timer */
    gettimeofday(&start_tv, NULL);

    for (i = 0; i < read_cnt; i++) {
        err = mpool_mdc_read(mdc, buf, args->rs, &bytes_read);
        if (err) {
            fprintf(
                stderr,
                "[%d]%s: error on read:%s\n",
                i,
                __func__,
                merr_strinfo(err, err_str, sizeof(err_str), NULL));
            resp->err = err;
            return resp;
        }
        ret = pattern_compare(buf, args->rs);
        if (ret) {
            fprintf(stderr, "[%d]%s: miscompare!\n", i, __func__);
            resp->err = merr(EIO);
            return resp;
        }
    }

    /* end timer */
    gettimeofday(&stop_tv, NULL);

    if (stop_tv.tv_usec < start_tv.tv_usec) {
        stop_tv.tv_sec--;
        stop_tv.tv_usec += 1000000;
    }
    usec = (stop_tv.tv_sec - start_tv.tv_sec) * 1000000 + (stop_tv.tv_usec - start_tv.tv_usec);

    resp->usec = usec;
    resp->verified = used;

    mpool_mdc_close(mdc);
    free(buf);

    return resp;
}

static merr_t
perf_seq_writes(const char *mpname, const struct hse_params *params)
{
    merr_t err = 0;
    u32    tc;
    int    i;
    int    err_cnt;
    char   err_str[256];
    u32    usec;
    u32    write_cnt;
    u64    per_thread_size;
    u64    bytes_written;
    u64    bytes_read;
    u64    bytes_verified;
    double perf;
    int    ret;

    struct ml_writer_resp *wr_resp;
    struct ml_writer_args *wr_arg;
    struct ml_reader_resp *rd_resp;
    struct ml_reader_args *rd_arg;
    struct ml_verify_resp *v_resp;
    struct ml_verify_args *v_arg;
    struct thread_args *   targ;
    struct thread_resp *   tresp;
    struct mpool *         mp;
    struct oid_pair *      oid;
    uint64_t               capacity;

    mclass = MP_MED_CAPACITY;
    tc = opt.threads;

    ret = pattern_base(NULL);
    if (ret == -1)
        return merr(EINVAL);

    err = mpool_open(mpname, params, O_RDWR, &mp);
    if (err) {
        fprintf(stderr, "Cannot open mpool %s\n", mpname);
        return err;
    }

    wr_arg = calloc(tc, sizeof(*wr_arg));
    targ = calloc(tc, sizeof(*targ));
    if (!wr_arg || !targ) {
        fprintf(stderr, "Unable to allocate memory for arguments\n");
        err = merr(ENOMEM);
        goto free_wr_arg;
    }

    tresp = calloc(tc, sizeof(*tresp));
    if (!tresp) {
        fprintf(stderr, "Unable to allocate memory for response pointers\n");
        err = merr(ENOMEM);
        goto free_targ;
    }

    per_thread_size = opt.cap / tc;
    capacity = per_thread_size;

    write_cnt = calc_record_count(per_thread_size, opt.recsz);
    if (write_cnt == 0) {
        fprintf(stderr, "No room to write even one record\n");
        err = merr(EINVAL);
        goto free_tresp;
    }

    oid = calloc(tc, sizeof(*oid));
    if (!oid) {
        fprintf(stderr, "Unable to alloc space for oid array\n");
        err = merr(ENOMEM);
        goto free_tresp;
    }

    for (i = 0; i < tc; i++) {

        /* Create an mdc */
        err = mpool_mdc_alloc(mp, 0xaabbcc00 + i, capacity, mclass, &oid[i].oid[0], &oid[i].oid[1]);
        if (err) {
            fprintf(
                stderr,
                "[%d]: Unable to alloc mdc: %s\n",
                i,
                merr_strinfo(err, err_str, sizeof(err_str), NULL));
            goto free_oid;
        }

        err = mpool_mdc_commit(mp, oid[i].oid[0], oid[i].oid[1]);
        if (err) {
            fprintf(
                stderr,
                "[%d]: Unable to commit mdc: %s\n",
                i,
                merr_strinfo(err, err_str, sizeof(err_str), NULL));
            goto free_oid;
        }

        wr_arg[i].mp = mp;
        wr_arg[i].rs = opt.recsz;
        wr_arg[i].wc = write_cnt;
        wr_arg[i].oid.oid[0] = oid[i].oid[0];
        wr_arg[i].oid.oid[1] = oid[i].oid[1];

        targ[i].arg = &wr_arg[i];
    }

    err = thread_create(tc, ml_writer, targ, tresp);
    if (err != 0) {
        fprintf(stderr, "Error from thread_create");
        goto free_oid;
    }

    usec = 0;
    bytes_written = 0;
    err_cnt = 0;

    for (i = 0; i < tc; i++) {
        wr_resp = tresp[i].resp;
        if (wr_resp->err) {
            err_cnt++;
        } else {
            usec = MAX(usec, wr_resp->usec);
            bytes_written += wr_resp->bytes_written;
        }
        free(wr_resp);
    }

    if (err_cnt) {
        fprintf(stderr, "thread reported error, exiting\n");
        _exit(-1);
    }
    perf = bytes_written / usec;
    printf(
        "%d threads wrote %ld bytes in %d usecs or %4.2f MB/s\n",
        tc,
        (long)bytes_written,
        usec,
        perf);

    /* Read */
    if (opt.mode == 2) {

        memset(targ, 0, tc * sizeof(*targ));
        memset(tresp, 0, tc * sizeof(*tresp));

        rd_arg = calloc(tc, sizeof(*rd_arg));
        if (!rd_arg) {
            fprintf(stderr, "%s: Unable to allocate memory for read arguments\n", __func__);
            return merr(ENOMEM);
        }

        for (i = 0; i < tc; i++) {

            rd_arg[i].mp = mp;
            rd_arg[i].rs = opt.recsz;
            rd_arg[i].rc = write_cnt;
            rd_arg[i].oid.oid[0] = oid[i].oid[0];
            rd_arg[i].oid.oid[1] = oid[i].oid[1];

            targ[i].arg = &rd_arg[i];
        }

        err = thread_create(tc, ml_reader, targ, tresp);
        if (err != 0) {
            fprintf(stderr, "%s: Error from thread_create", __func__);
            return err;
        }

        usec = 0;
        bytes_read = 0;
        err_cnt = 0;

        for (i = 0; i < tc; i++) {
            rd_resp = tresp[i].resp;
            if (rd_resp->err) {
                err_cnt++;
            } else {
                usec = MAX(usec, rd_resp->usec);
                bytes_read += rd_resp->read;
            }
            free(rd_resp);
        }

        if (err_cnt) {
            fprintf(stderr, "%s: thread reported error, exiting\n", __func__);
            _exit(-1);
        }
        perf = bytes_read / usec;
        printf(
            "%s: %d threads read %ld bytes in %d usecs or %4.2f MB/s\n",
            __func__,
            tc,
            (long)bytes_read,
            usec,
            perf);
    }

    /* Verify */
    if (opt.verify) {

        memset(targ, 0, tc * sizeof(*targ));
        memset(tresp, 0, tc * sizeof(*tresp));

        v_arg = calloc(tc, sizeof(*v_arg));
        if (!v_arg) {
            fprintf(stderr, "%s: Unable to allocate memory for read arguments\n", __func__);
            return merr(ENOMEM);
        }

        for (i = 0; i < tc; i++) {

            v_arg[i].mp = mp;
            v_arg[i].rs = opt.recsz;
            v_arg[i].rc = write_cnt;
            v_arg[i].oid.oid[0] = oid[i].oid[0];
            v_arg[i].oid.oid[1] = oid[i].oid[1];

            targ[i].arg = &v_arg[i];
        }

        err = thread_create(tc, ml_verify, targ, tresp);
        if (err != 0) {
            fprintf(stderr, "%s: Error from thread_create", __func__);
            free(v_arg);
            return err;
        }

        usec = 0;
        bytes_verified = 0;
        err_cnt = 0;

        for (i = 0; i < tc; i++) {
            v_resp = tresp[i].resp;
            if (v_resp->err) {
                err_cnt++;
            } else {
                usec = MAX(usec, v_resp->usec);
                bytes_verified += v_resp->verified;
            }
            free(v_resp);
        }

        if (err_cnt) {
            fprintf(stderr, "%s: thread reported error, exiting\n", __func__);
            _exit(-1);
        }
        perf = bytes_verified / usec;
        printf(
            "%s: %d threads verified %ld bytes in %d usecs or %4.2f MB/s\n",
            __func__,
            tc,
            (long)bytes_verified,
            usec,
            perf);

        free(v_arg);
    }

free_oid:
    for (i = 0; i < tc; i++) {
        if (oid[i].oid[0] || oid[i].oid[1]) {
            err = mpool_mdc_delete(mp, oid[i].oid[0], oid[i].oid[1]);
            if (err) {
                merr_strinfo(err, err_str, sizeof(err_str), NULL);
                fprintf(stderr, "[%d]: unable to destroy mdc: %s\n", i, err_str);
            }
        }
    }
    free(oid);

free_tresp:
    free(tresp);
free_targ:
    free(targ);
free_wr_arg:
    mpool_close(mp);
    free(wr_arg);

    return err;
}

merr_t
perf_seq_reads(const char *mpname, const struct hse_params *params)
{
    return perf_seq_writes(mpname, params);
}

struct option longopts[] = {
    { "recsz", required_argument, NULL, 'r' },   { "cap", required_argument, NULL, 'c' },
    { "threads", required_argument, NULL, 't' }, { "mode", required_argument, NULL, 'm' },
    { "verify", no_argument, NULL, 'v' },        { "sync", no_argument, NULL, 's' },
    { "help", no_argument, NULL, 'h' },          { 0, 0, 0, 0 }
};

static void
options_defaults_set(void)
{
    opt.recsz = 64;
    opt.cap = 2UL << 30;
    opt.threads = 1;
    opt.mode = 1;
    opt.verify = false;
    opt.sync = false;
    opt.help = false;
}

static void
usage(void)
{
    printf("usage: %s [options] [param=value ...]\n", progname);
    printf("Options:\n"
           "  -r, --recsz       record size\n"
           "  -c, --cap         MDC capacity\n"
           "  -t, --threads     number of threads\n"
           "  -m, --mode        1 - write, 2 - read-write\n"
           "  -v, --verify      verify data\n"
           "  -s, --sync        issue sync appends\n"
           "  -h, --help        help\n"
           "\n");
}

static void
options_parse(int argc, char **argv, int *last_arg)
{
    char *optstring = "r:c:t:m:vsh";

    do {
        int c;
        int optidx = 0;
        int curind = optind;

        c = getopt_long(argc, argv, optstring, longopts, &optidx);
        if (c == -1)
            break;

        switch (c) {
            case 'r':
                parse_u64(optarg, &opt.recsz);
                break;

            case 'c':
                parse_u64(optarg, &opt.cap);
                break;

            case 't':
                parse_u16(optarg, &opt.threads);
                break;

            case 'm':
                parse_u16(optarg, &opt.mode);
                break;

            case 'v':
                opt.verify = true;
                break;

            case 's':
                opt.sync = true;
                break;

            case 'h':
                opt.help = true;
                break;

            default:
                if (c != 0)
                    fprintf(stderr, "Unhandled option '%s'", argv[curind]);
                usage();
                break;
        };
    } while (true);

    *last_arg = optind;
}

int
main(int argc, char **argv)
{
    uint64_t           herr;
    struct hse_params *params;
    int                last_arg;

    const char *mpname = "mdcperf";

    progname = strrchr(argv[0], '/');
    progname = progname ? progname + 1 : argv[0];

    options_defaults_set();

    options_parse(argc, argv, &last_arg);

    if (opt.help) {
        usage();
        return 0;
    }

    herr = hse_kvdb_init();
    if (herr)
        return -1;

    herr = hse_params_create(&params);
    if (herr) {
        hse_kvdb_fini();
        return -1;
    }

    herr = hse_parse_cli(argc - last_arg, argv + last_arg, &last_arg, 0, params);
    if (herr) {
        usage();
        hse_params_destroy(params);
        hse_kvdb_fini();
        return -1;
    }

    if (opt.mode == 1)
        perf_seq_writes(mpname, params);
    else
        perf_seq_reads(mpname, params);

    hse_params_destroy(params);

    hse_kvdb_fini();

    return 0;
}
