/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <clang-c/CXCompilationDatabase.h>
#include <clang-c/Index.h>

#include "commands/header.h"
#include "commands/source.h"
#include "commands/symbol-table.h"
#include "mkmock.h"
#include "mock.h"

static struct option long_options[] = {
    { "help", no_argument, 0, 'h' },
    { "builddir", required_argument, 0, 'b' },
    { "includedir", required_argument, 0, 'i' },
    { "output", required_argument, 0, 'o' },
    { NULL, 0, 0, 0 },
};

FILE *output;
const char *builddir;
char includedir[PATH_MAX];
CXCompilationDatabase database;

void
usage(FILE *stream)
{
    fprintf(stream, "Usage: mkmock [-h]\n\n");
    fprintf(stream, "Options:\n");
    fprintf(stream, "\t-h, --help \t Print help\n");
}

int
main(const int argc, char **argv)
{
    int c, rc;

    output = stdout;

    while (true) {
        int option_index = 0;

        c = getopt_long(argc, argv, "+:hb:i:o:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            builddir = optarg;
            break;
        case 'i':
            strncpy(includedir, optarg, sizeof(includedir) - 1);
            break;
        case 'h':
            usage(stdout);
            return 0;
        case 'o':
            output = fopen(optarg, "w");
            if (!output) {
                fprintf(stderr, "Failed to open output file (%s): %s\n", optarg, strerror(errno));
                return EX_USAGE;
            }
        }
    }

    if (!builddir) {
        fprintf(stderr, "Missing required argument: builddir\n");
        usage(stderr);
        return EX_USAGE;
    }

    if (includedir[0] == '\0') {
        FILE *pout;
        char resource_dir[PATH_MAX];

        pout = popen("clang -print-resource-dir", "r");
        if (!pout) {
            fprintf(stderr, "Failed to get the clang resource directory: %s", strerror(errno));
            return EX_OSERR;
        }

        fgets(resource_dir, sizeof(resource_dir), pout);
        rc = pclose(pout);
        if (rc != 0) {
            fprintf(stderr, "Failed to get the clang resource directory: %s", strerror(errno));
            return EX_OSERR;
        }

        rc = snprintf(includedir, sizeof(includedir), "%.*s/include", (int)(strlen(resource_dir) - 1), resource_dir);
        if (rc < 0 || (size_t)rc >= sizeof(includedir)) {
            fputs("Failed to get the clang include directory", stderr);
            return EX_OSERR;
        }
    }

    mock_init();

    CXCompilationDatabase_Error error;
    database = clang_CompilationDatabase_fromDirectory(builddir, &error);
    if (error) {
        fprintf(stderr, "Failed to read the compilation database\n");
        return EX_IOERR;
    }

    if (strcmp(argv[optind], SYMBOL_TABLE) == 0) {
        rc = symbol_table(argc - optind, argv + optind);
        if (rc) {
            fprintf(stderr, "Failed to generate the symbol table\n");
            return rc;
        }
    } else if (strcmp(argv[optind], HEADER) == 0) {
        rc = header(argc - optind, argv + optind);
        if (rc) {
            fprintf(stderr, "Failed to generate the header file\n");
            return rc;
        }
    } else if (strcmp(argv[optind], SOURCE) == 0) {
        rc = source(argc - optind, argv + optind);
        if (rc) {
            fprintf(stderr, "Failed to generate the source file\n");
            return rc;
        }
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[optind]);
        usage(stderr);
        return EX_USAGE;
    }

    clang_CompilationDatabase_dispose(database);

    mock_fini();

    return 0;
}
