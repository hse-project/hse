/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc. All rights reserved.
 */

/*
 * attack - create hostile key insert patterns for wbt testing
 *
 * attack is the simplest such client that allows variations of
 * sequentially inserted keys of generally constant length,
 * with large keys inserted periodically as directed.
 *
 * This tool is used for surgical tests of kvs internals,
 * and does not represent any possible real life application.
 * Keys are NOT verified -- this is left to visual inspection
 * with cndump.
 */

#include <arpa/inet.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <hse/cli/program.h>
#include <hse/hse.h>
#include <hse/util/compiler.h>
#include <hse/util/inttypes.h>

void HSE_PRINTF(2, 3)
fatal(hse_err_t err, char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    if (err)
        fprintf(stderr, ": %ld\n", (long)err);
    else
        fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

void HSE_PRINTF(1, 2)
syntax(const char *fmt, ...)
{
    char    msg[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s: %s, use -h for help\n", progname, msg);
}

void
usage(void)
{
    printf("usage: %s [-{lcsaer} n] [-o opt] kvdb kvs\n", progname);
    printf("-a n       attack key length is $n\n"
           "-c n       put $n sequential binary keys\n"
           "-e n       attack every $nth put\n"
           "-l n       use $n len keys\n"
           "-o s       override ikvs configuration variable\n"
           "-r n       attack approximately $n%% of puts\n"
           "-s n       start sequence at $n\n"
           "-Z config  path to global config file\n"
           "\nattack generates worst-case binary key lengths puts "
           "sequentially from 1 for 1000 keys\n");
}

int
main(int argc, char **argv)
{
    u64 rc;
    int c, last;
    char *mpname;
    uint32_t *seq;
    char data[4096];
    size_t keylen, alen;
    const char *kvsname;
    struct hse_kvs *kvs;
    struct hse_kvdb *kvdb;
    const char *config = NULL;
    int cnt, start, every, rdm;

    progname_set(argv[0]);

    keylen = 4;
    cnt = 1000;
    start = 1;
    alen = 1000;
    every = 153;
    rdm = 0;

    while ((c = getopt(argc, argv, ":a:c:e:hl:o:r:s:Z:")) != -1) {
        switch (c) {
            case 'a':
                alen = strtoul(optarg, 0, 0);
                break;
            case 'c':
                cnt = (int)strtoul(optarg, 0, 0);
                break;
            case 'e':
                every = (int)strtoul(optarg, 0, 0);
                break;
            case 'Z':
                config = optarg;
                break;
            case 'h':
                usage();
                exit(0);
            case 'l':
                keylen = strtoul(optarg, 0, 0);
                break;
            case 'r':
                rdm = (int)strtoul(optarg, 0, 0);
                break;
            case 's':
                start = (int)strtoul(optarg, 0, 0);
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

    if (argc < 3) {
        syntax("insufficient arguments for mandatory parameters");
        exit(EX_USAGE);
    } else if (argc > 3) {
        syntax("extraneous arguments ignored");
    }

    mpname = argv[0];
    kvsname = argv[1];

    rc = hse_init(config, 0, NULL);
    if (rc)
        fatal(rc, "failed to initialize kvdb");

    rc = hse_kvdb_open(mpname, 0, NULL, &kvdb);
    if (rc)
        fatal(rc, "cannot open kvdb %s/%s", mpname, kvsname);

    rc = hse_kvdb_kvs_open(kvdb, kvsname, 0, NULL, &kvs);
    if (rc)
        fatal(rc, "cannot open kvs %s/%s", mpname, kvsname);

    printf("writing %d binary keys of len %zu, starting with %08x\n", cnt, keylen, start);

    for (size_t i = 0; i < sizeof(data); ++i)
        data[i] = (char)(i & 0xff);

    seq = (uint32_t *)data;

    srandom((uint)getpid());

    last = start + cnt;
    for (int i = start; i < last; ++i) {
        void * key, *val;
        size_t klen, vlen;

        *seq = htonl((uint32_t)i);

        if (rdm == 0)
            klen = i % every == 0 ? alen : keylen;
        else
            klen = random() % 100 < rdm ? alen : keylen;

        key = data;
        vlen = keylen;
        val = data;

        rc = hse_kvs_put(kvs, 0, NULL, key, klen, val, vlen);
        if (rc)
            fatal(rc, "hse_kvs_put");
    }

    rc = hse_kvdb_close(kvdb);
    if (rc) {
        fatal(rc, "kvs_close");
        exit(1);
    }

    hse_fini();

    return 0;
}
