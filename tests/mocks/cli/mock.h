/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MKMOCK_MOCK_H
#define MKMOCK_MOCK_H

#include <stdbool.h>

#include <clang-c/Index.h>

struct argument {
    char *type;
    char *name;
};

struct mock {
    enum CXTypeKind return_type_kind;
    char *return_type_name;
    char *function_name;
    size_t argc;
    struct argument *argv;
    bool is_variadic;
};

extern size_t num_mocks;
extern size_t cap_mocks;
extern struct mock *mocks;

int
mock_init(void);

void
mock_fini(void);

int
mock_collect(const char *file);

#endif
