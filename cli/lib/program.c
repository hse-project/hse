/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <string.h>

#include <hse/cli/program.h>

const char *progname;

void
progname_set(const char * const argv_0)
{
    const char *slash;

    slash = strrchr(argv_0, '/');
    if (slash) {
        progname = slash + 1;
    } else {
        progname = argv_0;
    }
}
