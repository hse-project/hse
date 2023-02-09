/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <stdarg.h>
#include <stdio.h>
#include <sysexits.h>

#include <hse/hse.h>

#include <hse/cli/program.h>

#include "fatal.h"
#include "globals.h"

void
fatal(const char *who, merr_t err)
{
    char buf[256];

    hse_strerror(err, buf, sizeof(buf));
    fprintf(stderr, "%s: %s: %s\n", progname, who, buf);
    exit(EX_OSERR);
}

void
syntax(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: ", progname);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, " (use -h for help)\n");

    exit(EX_USAGE);
}
