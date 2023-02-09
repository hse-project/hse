/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <hse/hse.h>

#include <hse/cli/program.h>
#include <hse/ikvdb/diag_kvdb.h>

#include "cndb_reader.h"
#include "cndb_record.h"
#include "commands.h"
#include "fatal.h"
#include "globals.h"

/* command line options for cndb sub-command */
struct opts {
    bool oneline;     // print each record on a single line
    const char *home; // KVDB home dir
};

static struct opts opts;

static void
help(void)
{
    printf("usage: %s %s [options] <kvdb_home>\n", progname, CNDB_COMMAND_NAME);
    printf("  -h           print help\n"
           "  -v           verbose\n"
           "  -l           show each record on a single line\n"
           "  <kvdb_home>  KVDB home directory\n");

    if (!global_opts.verbose) {
        printf("use '-hv' for more detail\n");
        return;
    }

    printf("\nDump a KVDB's CNDB log on standard output.\n\n");
    printf("The CNDB log is a transactional log containing CN tree mutations.  It shows\n");
    printf("information such as CN tree node IDs, KVS names, kvset IDs, hblock, kbock and \n");
    printf("vblock IDs.  Use this command to get kvset and mblock IDs that can be used\n");
    printf(
        "with '%s %s' and '%s %s'.\n", CNDB_COMMAND_NAME, KVSET_COMMAND_NAME, CNDB_COMMAND_NAME,
        MBLOCK_COMMAND_NAME);
}

static void
parse_args(int argc, char **argv)
{
    int c;

    while ((c = getopt(argc, argv, "+:hvl")) != -1) {
        switch (c) {
        case 'h':
            global_opts.help = true;
            break;
        case 'v':
            global_opts.verbose = true;
            break;
        case 'l':
            opts.oneline = true;
            break;
        case ':':
            syntax("option -%c requires a parameter", optopt);
            break;
        default:
            syntax("invalid %s option: -%c", CNDB_COMMAND_NAME, optopt);
            break;
        }
    }

    if (global_opts.help) {
        help();
        exit(0);
    }

    if (optind == argc)
        syntax("missing <kvdb_home> parameter");

    opts.home = argv[optind++];

    if (optind != argc)
        syntax("unexpected parameter: '%s'", argv[optind]);
}

void
cndb_cmd(int argc, char **argv)
{
    const char *paramv[] = { "rest.enabled=false" };
    struct cndb_dump_reader reader;
    struct cndb_rec rec;
    struct hse_kvdb *kvdb;
    merr_t err;

    parse_args(argc, argv);

    err = hse_init(0, NELEM(paramv), paramv);
    if (err)
        fatal("hse_init", err);

    err = diag_kvdb_open(opts.home, 0, 0, &kvdb);
    if (err)
        fatal("diag_kvdb_open", err);

    cndb_iter_init(kvdb, &reader);
    cndb_rec_init(&rec);
    while (cndb_iter_next(&reader, &rec))
        cndb_rec_print(&rec, opts.oneline);
    cndb_rec_fini(&rec);

    err = diag_kvdb_close(kvdb);
    if (err)
        fatal("diag_kvdb_close", err);

    hse_fini();
}
