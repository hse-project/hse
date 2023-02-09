/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>

#include <sys/stat.h>

#include <hse/error/merr.h>
#include <hse/util/table.h>

static const char *program;
static bool check;
static size_t key_length = 32;
static size_t value_length = 32;
static struct table *hblocks;
static struct table *kblocks;
static struct table *vblocks;

static void
usage(FILE *stream)
{
    fprintf(stream, "output\n");
}

int
main(int argc, char **argv)
{
    static const struct option longopts[] = {
        { "check-only", no_argument, NULL, 'c' },
        { "hblock", no_argument, NULL, 'H' },
        { "help", no_argument, NULL, 'h' },
        { "kblock", required_argument, NULL, 'K' },
        { "key-length", required_argument, NULL, 'k' },
        { "value-length", required_argument, NULL, 'v' },
        { "vblock", required_argument, NULL, 'V' },
        { 0 },
    };

    int c;
    int idx;
    int rc = 0;
    struct stat st;
    char path[PATH_MAX];

    program = strrchr(argv[0], '/');
    program = program ? program + 1 : argv[0];

    hblocks = table_create(8, sizeof(*argv), true);
    kblocks = table_create(8, sizeof(*argv), true);
    vblocks = table_create(8, sizeof(*argv), true);
    if (!hblocks || !kblocks || !vblocks) {
        fprintf(stderr, "Out of memory\n");
        rc = EX_OSERR;
        goto out;
    }

    while ((c = getopt_long(argc, argv, "+:hk:v:z:", longopts, &idx)) != -1) {
        switch (c) {
        case 'c':
            check = true;
            break;
        case 'h':
            usage(stdout);
            goto out;
        case 'H':
            if (!table_append_object(hblocks, optarg)) {
                fprintf(stderr, "Out of memory\n");
                rc = EX_OSERR;
                goto out;
            }

            break;
        case 'k': {
            char *end;

            key_length = strtoull(optarg, &end, 10);
            if (!end) {
                fprintf(stderr, "Failed to convert %s to number\n", optarg);
                rc = EX_USAGE;
                goto out;
            }

            break;
        }
        case 'K':
            if (!table_append_object(kblocks, optarg)) {
                fprintf(stderr, "Out of memory\n");
                rc = EX_OSERR;
                goto out;
            }

            break;
        case 'v': {
            char *end;

            value_length = strtoull(optarg, &end, 10);
            if (!end) {
                fprintf(stderr, "Failed to convert %s to number\n", optarg);
                rc = EX_USAGE;
                goto out;
            }

            break;
        }
        case 'V':
            if (!table_append_object(vblocks, optarg)) {
                fprintf(stderr, "Out of memory\n");
                rc = EX_OSERR;
                goto out;
            }

            break;
        case ':':
            fprintf(stderr, "Option -%c/--%s requires a parameter\n", optopt, longopts[idx].name);
            rc = EX_USAGE;
            goto out;
        case '?':
            fprintf(stderr, "Invalid option -%c\n", optopt);
            rc = EX_USAGE;
            goto out;
        default:
            fprintf(stderr, "Option -%c ignored\n", c);
            break;
        }
    }

    if (!realpath(argv[optind], path)) {
        rc = EX_OSFILE;
        goto out;
    }

    rc = stat(path, &st);
    if (rc == -1) {
        rc = EX_OSERR;
        goto out;
    }

    if (S_ISDIR(st.st_mode)) {

    } else {
    }

out:
    table_destroy(hblocks);
    table_destroy(kblocks);
    table_destroy(vblocks);

    return rc;
}
