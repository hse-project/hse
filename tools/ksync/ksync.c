/*
 * Copyright (C) 2017 Micron Technology, Inc.  All rights reserved.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/time.h>

#include <hse/hse.h>

#include <hse_util/inttypes.h>
#include <hse_util/arch.h>

#include <tools/parm_groups.h>

const char *progname, *mp_name, *kvs_name;
ulong       kwrite, kflush, ksync, ktxn;
ulong       keymax;
size_t      vlenmin = 0;
size_t      vlenmax = 1024;
int         verbosity;

struct parm_groups *pg;
struct svec          db_oparm;
struct svec          kv_oparm;

__attribute__((format(printf, 2, 3))) void
herr_print(uint64_t herr, char *fmt, ...)
{
    char    msg_buf[256];
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    if (herr) {
        hse_err_to_string(herr, msg_buf, sizeof(msg_buf));
        fprintf(stderr, "%s", msg_buf);
    }
}

__attribute__((format(printf, 1, 2))) void
eprint(char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: ", progname);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

__attribute__((format(printf, 1, 2))) void
syntax(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: ", progname);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void
stuff(void)
{
    struct timeval tstart, tstop, tdiff;

    struct hse_kvdb *kvdb;
    struct hse_kvs * kvs;
    size_t           klen, vlen;
    u64              key;
    u64 *            val;
    long             usecs;
    uint64_t         herr;
    uint             i;

    klen = sizeof(key);
    key = 0;

    val = malloc(vlenmax + klen);
    if (!val) {
        eprint("malloc(%zu) failed", vlenmax + klen);
        exit(EX_OSERR);
    }

    memset(val, 0, vlenmax + klen);

    herr = hse_kvdb_open(mp_name, db_oparm.strc, db_oparm.strv, &kvdb);
    if (herr) {
        herr_print(herr, "hse_kvdb_open(%s) failed: ", mp_name);
        exit(EX_NOINPUT);
    }

    herr = hse_kvdb_kvs_open(kvdb, kvs_name, kv_oparm.strc, kv_oparm.strv, &kvs);
    if (herr) {
        herr_print(herr, "hse_kvdb_kvs_open(%s) failed: ", mp_name);
        exit(EX_NOINPUT);
    }

    if (kflush > 0) {
        gettimeofday(&tstart, NULL);

        for (i = 0; i < kflush; ++i) {
            if (keymax > 0) {
                key = i % keymax;
                *val = key;
                vlen = vlenmin;
                vlen += get_cycles() % (vlenmax - vlenmin + 1);

                herr = hse_kvs_put(kvs, 0, NULL, &key, klen, val, vlen);
                if (herr) {
                    herr_print(herr, "hse_kvs_put() failed: ");
                    break;
                }
            }

            herr = hse_kvdb_sync(kvdb, HSE_FLAG_SYNC_ASYNC);
            if (herr) {
                herr_print(herr, "hse_kvdb_sync() failed: ");
                break;
            }
        }

        gettimeofday(&tstop, NULL);
        timersub(&tstop, &tstart, &tdiff);
        usecs = tdiff.tv_sec * 1000000.0 + tdiff.tv_usec;

        if (verbosity > 0)
            printf("%.3f flush/sec\n", (i * 1000000.0) / usecs);
    }

    if (ksync > 0) {
        gettimeofday(&tstart, NULL);

        for (i = 0; i < ksync; ++i) {
            if (keymax > 0) {
                key = i % keymax;
                *val = key;
                vlen = vlenmin;
                vlen += get_cycles() % (vlenmax - vlenmin + 1);

                herr = hse_kvs_put(kvs, 0, NULL, &key, klen, val, vlen);
                if (herr) {
                    herr_print(herr, "hse_kvs_put() failed: ");
                    break;
                }
            }

            herr = hse_kvdb_sync(kvdb, 0);
            if (herr) {
                herr_print(herr, "hse_kvdb_sync() failed: ");
                break;
            }
        }

        gettimeofday(&tstop, NULL);
        timersub(&tstop, &tstart, &tdiff);
        usecs = tdiff.tv_sec * 1000000.0 + tdiff.tv_usec;

        if (verbosity > 0)
            printf("%.3f sync/sec\n", (i * 1000000.0) / usecs);
    }

    if (ktxn > 0) {
        struct hse_kvdb_txn *  txn;

        gettimeofday(&tstart, NULL);

        txn = hse_kvdb_txn_alloc(kvdb);
        if (!txn)
            abort();

        for (i = 0; i < ktxn; ++i) {
            herr = hse_kvdb_txn_begin(kvdb, txn);
            if (herr) {
                herr_print(herr, "hse_kvdb_txn_begin() failed: ");
                abort();
            }

            if (keymax > 0) {
                key = i % keymax;
                *val = key;
                vlen = vlenmin;
                vlen += get_cycles() % (vlenmax - vlenmin + 1);

                herr = hse_kvs_put(kvs, 0, txn, &key, klen, val, vlen);
                if (herr) {
                    herr_print(herr, "hse_kvs_put() failed: ");
                    break;
                }
            }

            herr = hse_kvdb_txn_commit(kvdb, txn);
            if (herr) {
                herr_print(herr, "hse_kvdb_txn_commit() failed: ");
                break;
            }
        }

        hse_kvdb_txn_free(kvdb, txn);

        gettimeofday(&tstop, NULL);
        timersub(&tstop, &tstart, &tdiff);
        usecs = tdiff.tv_sec * 1000000.0 + tdiff.tv_usec;

        if (verbosity > 0)
            printf("%.3f txn/sec\n", (i * 1000000.0) / usecs);
    }

    herr = hse_kvdb_close(kvdb);
    if (herr)
        herr_print(herr, "hse_kvdb_close() failed: ");

    free(val);
}

void
usage(void)
{
    printf("usage: %s [options] <kvdb> <kvs> [kvs_param=value ...]\n", progname);
    printf("usage: %s -h [-v]\n", progname);

    printf("-f flush   specify how many times to call c0sk_flush\n");
    printf("-h         print this help list\n");
    printf("-j jobs    specify max number of jobs\n");
    printf("-k keys    specify max number of keys to put\n");
    printf("-l vlen    specify [min:]max value length\n");
    printf("-s sync    specify how many times to call c0sk_sync\n");
    printf("-t txn     specify how many times to issue a transaction\n");
    printf("-v         increase verbosity\n");
    printf("\n");
}

int
main(int argc, char **argv)
{
    uint64_t herr;
    bool     help = false;
    int      rc;

    progname = strrchr(argv[0], '/');
    progname = progname ? progname + 1 : argv[0];

    rc = pg_create(&pg, PG_KVDB_OPEN, PG_KVS_OPEN, NULL);
    if (rc) {
        eprint("pg_create failed");
        exit(EX_OSERR);
    }

    while (1) {
        char *errmsg, *end;
        int   c;

        c = getopt(argc, argv, ":hf:j:k:l:s:t:Vv");
        if (-1 == c)
            break;

        errmsg = end = NULL;
        errno = 0;

        switch (c) {
            case 'f':
                kflush = strtoul(optarg, &end, 0);
                errmsg = "invalid flush count";
                break;

            case 'h':
                help = true;
                break;

            case 'k':
                keymax = strtoul(optarg, &end, 0);
                errmsg = "invalid keymax count";
                break;

            case 'l':
                vlenmax = strtoul(optarg, &end, 0);
                vlenmin = vlenmax;
                if (*end == ':')
                    vlenmax = strtoul(end + 1, &end, 0);
                if (vlenmax < vlenmin)
                    vlenmax = vlenmin;
                errmsg = "invalid value length";
                break;

            case 's':
                ksync = strtoul(optarg, &end, 0);
                errmsg = "invalid sync count";
                break;

            case 't':
                ktxn = strtoul(optarg, &end, 0);
                errmsg = "invalid transacton count";
                break;

            case 'v':
                ++verbosity;
                break;

            case '?':
                syntax("invalid option -%c", optopt);
                exit(EX_USAGE);

            case ':':
                syntax("option -%c requires a parameter", optopt);
                exit(EX_USAGE);

            default:
                eprint("option -%c ignored\n", c);
                break;
        }

        if (errmsg && errno) {
            syntax("%s", errmsg);
            exit(EX_USAGE);
        } else if (end && *end) {
            syntax("%s '%s'", errmsg, optarg);
            exit(EX_USAGE);
        }
    }

    if (help) {
        usage();
        exit(0);
    }

    if (argc - optind < 2) {
        syntax("insufficient arguments for mandatory parameters");
        exit(EX_USAGE);
    }

    mp_name  = argv[optind++];
    kvs_name = argv[optind++];

    rc = pg_parse_argv(pg, argc, argv, &optind);
    switch (rc) {
        case 0:
            if (optind < argc) {
                eprint("unknown parameter: %s", argv[optind]);
                exit(EX_USAGE);
            }
            break;
        case EINVAL:
            eprint("missing group name (e.g. %s) before parameter %s\n",
                PG_KVDB_OPEN, argv[optind]);
            exit(EX_USAGE);
            break;
        default:
            eprint("error processing parameter %s\n", argv[optind]);
            exit(EX_OSERR);
            break;
    }

    rc = rc ?: svec_append_pg(&db_oparm, pg, "perfc_enable=0", PG_KVDB_OPEN, NULL);
    rc = rc ?: svec_append_pg(&kv_oparm, pg, PG_KVS_OPEN, "transactions_enable=1", NULL);
    if (rc) {
        eprint("svec_append_pg failed: %d", rc);
        exit(EX_OSERR);
    }

    herr = hse_init(0, NULL);
    if (herr) {
        herr_print(herr, "hse_init(0, NULL) failed: ");
        exit(EX_OSERR);
    }

    stuff();

    pg_destroy(pg);
    svec_reset(&db_oparm);
    svec_reset(&kv_oparm);

    hse_fini();

    return 0;
}
