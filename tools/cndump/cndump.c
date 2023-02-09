/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <stdarg.h>
#include <stdio.h>

#include <hse/hse.h>

#include <hse/cli/program.h>
#include <hse/ikvdb/cndb.h>
#include <hse/ikvdb/diag_kvdb.h>
#include <hse/mpool/mpool.h>

#include "cn/kvset.h"
#include "cndb/omf.h"
#include "cndb_reader.h"
#include "commands.h"
#include "fatal.h"
#include "globals.h"

/* globals */
struct global_opts global_opts;

static void
help(void)
{
    printf("usage: %s [options] <sub-command> ...\n", progname);
    printf("options:\n");
    printf("  -h        print help\n");
    printf("  -v        be verbose\n");
    printf("sub-commands:\n");
    printf("  %-8s  %s\n", CNDB_COMMAND_NAME, CNDB_COMMAND_DESC);
    printf("  %-8s  %s\n", KVSET_COMMAND_NAME, KVSET_COMMAND_DESC);
    printf("  %-8s  %s\n", MBLOCK_COMMAND_NAME, MBLOCK_COMMAND_DESC);

    if (!global_opts.verbose) {
        printf("use '-hv' for more detail\n");
        return;
    }

    printf("\n");
    printf("%s dump KVDB OMF objects in human readable form.\n", progname);
    printf("Use '<sub-command> -h' to get help on individual sub-commands.\n");
}

static void
parse_args(int argc, char **argv)
{
    int c;

    while ((c = getopt(argc, argv, "+:hv")) != -1) {
        switch (c) {
        case 'h':
            global_opts.help = true;
            break;
        case 'v':
            global_opts.verbose = true;
            break;
        case ':':
            syntax("option -%c requires a parameter", optopt);
            break;
        default:
            syntax("invalid option -%c", optopt);
            break;
        }
    }
}

int
main(int argc, char **argv)
{
    const char *cmd;

    progname_set(argv[0]);

    parse_args(argc, argv);

    if (global_opts.help) {
        help();
        exit(0);
    }

    if (optind == argc)
        syntax("missing <command>");

    cmd = argv[optind];
    argc -= optind;
    argv += optind;
    optind = 0;

    if (!strcmp(cmd, CNDB_COMMAND_NAME))
        cndb_cmd(argc, argv);
    else if (!strcmp(cmd, KVSET_COMMAND_NAME))
        kvset_cmd(argc, argv);
    else if (!strcmp(cmd, MBLOCK_COMMAND_NAME))
        mblock_cmd(argc, argv);
    else
        syntax("invalid command: '%s'", cmd);

    return 0;
}
