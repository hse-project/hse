/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2018,2021 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <string.h>

#include <hse/hse.h>

const char *kfmt = "k%u";
uint        kmax = 100;

struct hse_kvdb *kvdb;
struct hse_kvs  *kvs;

const char *progname;

void
syntax(const char *fmt, ...)
{
    char msg[2048];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s: %s, use -h for help\n", progname, msg);
}

void
fatal(hse_err_t err, const char *fmt, ...)
{
    char msgbuf[1024];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msgbuf, sizeof(msgbuf) - 128, fmt, ap);
    va_end(ap);

    if (err) {
        size_t len = strlen(strcat(msgbuf, ": "));

        hse_strerror(err, msgbuf + len, sizeof(msgbuf) - len);
    }

    fprintf(stderr, "%s: %s\n", progname, msgbuf);

    hse_kvdb_close(kvdb);
    exit(EX_SOFTWARE);
}

void
usage(void)
{
    printf("usage: %s [options] <kvdb> <kvs>\n", progname);
    printf("-c <count>  read/write <count> k/v pairs (default: %u)\n", kmax);
    printf("-f <fmt>    specify key printf format (default: \"%s\")\n", kfmt);
    printf("-h          print this help list\n");
    printf("-r          read and verify key/value pairs\n");
    printf("-v          be verbose\n");
    printf("-w          write key/value pairs\n");
    printf("\n");
}

void
simple_client(
    const char *mp_name,
    const char *kvs_name,
    bool        read,
    bool        write,
    bool        verbose)
{
    char    key[HSE_KVS_KEY_LEN_MAX + 1];
    char    val[32], xval[32];
    size_t  klen, klenmax;
    size_t  vlen, vlenmax;
    size_t  xlen;
    bool    found;
    uint    i;
    hse_err_t err;

    klenmax = snprintf(key, sizeof(key), kfmt, kmax, kmax, kmax);
    if (klenmax > sizeof(key) - 1)
        fatal(EINVAL,
              "key format at %u yields key longer than %zu bytes",
              kmax, sizeof(key) - 1);

    vlenmax = snprintf(val, sizeof(val), "v%08d", kmax);

    err = hse_kvdb_open(mp_name, 0, NULL, &kvdb);
    if (err)
        fatal(err, "hse_kvdb_open(%s) failed", mp_name);

    err = hse_kvdb_kvs_open(kvdb, kvs_name, 0, NULL, &kvs);
    if (err)
        fatal(err, "hse_kvdb_kvs_open(%s) failed", kvs_name);

    for (i = 0; write && i < kmax; i++) {
        klen = snprintf(key, sizeof(key), kfmt, i, i, i);
        assert(klen > 0 && klen < sizeof(key));

        /* Every other value is longer than 8 bytes in order
         * to exercise both kblock and vblock value storage.
         */
        vlen = snprintf(val, sizeof(val),
                        (i & 1) ? "v%08u" : "v%u", i);
        assert(vlen > 1 && vlen < sizeof(val));

        if (verbose)
            printf("put %8d:  %*s  %*s\n",
                   i, (int)klenmax, key, (int)vlenmax, val);

        err = hse_kvs_put(kvs, 0, NULL, key, klen, val, vlen);
        if (err)
            fatal(err, "hse_kvs_put(%s, %zu, %s, %zu) failed",
                  key, klen, val, vlen);
    }

    for (i = 0; read && i < kmax; i++) {
        klen = snprintf(key, sizeof(key), kfmt, i, i, i);

        err = hse_kvs_get(kvs, 0, NULL, key, klen, &found,
                          val, sizeof(val), &vlen);
        if (err)
            fatal(err, "hse_kvs_get(%s, %zu) failed", key, klen);
        if (!found)
            fatal(ENOENT, "key %s not found", key);

        val[vlen] = '\000';

        xlen = snprintf(xval, sizeof(xval),
                        (i & 1) ? "v%08u" : "v%u", i);

        if (verbose)
            printf("get %8d:  %*s  %*s\n",
                   i, (int)klenmax, key, (int)vlenmax, val);

        if (xlen != vlen)
            fatal(EINVAL,
                  "value length mismatch: key %s, exp %d, got %d",
                  key, xlen, vlen);

        if (0 != strcmp(xval, val))
            fatal(EINVAL,
                  "value data mismatch: key %s, exp %s, got %s",
                  key, xval, val);
    }

    err = hse_kvdb_close(kvdb);
    if (err)
        fatal(err, "hse_kvdb_close");
}

int
main(int argc, char **argv)
{
    int c, rc;
    bool verbose = false;
    bool read = false;
    bool write = false;
    const char *mp_name;
    const char *kvs_name;

    progname = strrchr(argv[0], '/');
    progname = progname ? progname + 1 : argv[0];

    while (-1 != (c = getopt(argc, argv, ":c:f:hrvw"))) {
        char *endptr = NULL;

        errno = 0;

        switch (c) {
        case 'c':
            kmax = strtoul(optarg, &endptr, 0);
            if (errno || *endptr) {
                syntax("unable to convert '-%c %s'", c, optarg);
                exit(EX_USAGE);
            }
            break;

        case 'f':
            kfmt = optarg;
            break;

        case 'h':
            usage();
            return 0;

        case 'r':
            read = true;
            break;

        case 'v':
            verbose = true;
            break;

        case 'w':
            write = true;
            break;

        case '?':
            syntax("invalid option -%c", optopt);
            exit(EX_USAGE);

        case ':':
            syntax("option -%c requires a parameter", optopt);
            exit(EX_USAGE);

        default:
            syntax("option -%c ignored\n", c);
            break;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc != 2) {
        syntax("invalid number of arguments");
        exit(EX_USAGE);
    }

    if (!read && !write)
        read = write = true;

    mp_name   = argv[0];
    kvs_name  = argv[1];

    if (verbose) {
        printf("mpool %s\n", mp_name);
        printf("kvs   %s\n", kvs_name);
        printf("count %u\n", kmax);
    }

    rc = hse_init(mp_name, 0, NULL);
    if (rc)
        fatal(rc, "failed to initalize kvdb");

    simple_client(mp_name, kvs_name, read, write, verbose);

    hse_fini();

    return 0;
}
