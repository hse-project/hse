/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#ifndef HSE_CLI_CONFIG_H
#define HSE_CLI_CONFIG_H

#include <stddef.h>

#include <hse/util/compiler.h>

/**
 * Create parameter array from argv
 *
 * Takes an arbitrary number of key=value pairs in the last argument. Call to
 * function must be NULL-terminated.
 *
 * @param argc: number of arguments
 * @param argv: array of arguments
 * @param[out] idx: index of next argument
 * @param[out] paramc: number of parameters
 * @param[out] paramv: array of parameters; if not-NULL, must be freed by caller
 */
int
params_from_argv(const int argc, char **argv, int *idx, size_t *paramc, const char ***paramv, ...)
    HSE_SENTINEL;

#endif
