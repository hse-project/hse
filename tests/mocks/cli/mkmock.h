/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MKMOCK_H
#define MKMOCK_H

#include <limits.h>
#include <stdio.h>

#include <clang-c/CXCompilationDatabase.h>

extern FILE *output;
extern const char *builddir;
extern char includedir[PATH_MAX];
extern CXCompilationDatabase database;

void
usage(FILE *stream);

#endif
