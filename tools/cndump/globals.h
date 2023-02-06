/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#ifndef CNDUMP_GLOBALS_H
#define CNDUMP_GLOBALS_H

#include <stdbool.h>

struct global_opts {
    bool help;
    bool verbose;
};

extern struct global_opts global_opts;

#endif
