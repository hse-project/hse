/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
params_from_argv(const int argc, char **argv, int *idx, size_t *paramc, char ***paramv, ...)
{
    int rc = 0;
    va_list params;

    if ((paramc && !paramv) || (!paramc && paramv))
        return EINVAL;

    if (!paramc && !paramv)
        goto non_va;

    va_start(params, paramv);

    for (char *param = va_arg(params, char *); param; param = va_arg(params, char *)) {
#ifndef NDEBUG
        const char *value = strstr(param, "=");
        assert(value && value[0] != '\0');
#endif

        (*paramc)++;
        *paramv = realloc(*paramv, (*paramc) * sizeof(char *));
        if (!*paramv) {
            rc = ENOMEM;
            break;
        }
        (*paramv)[(*paramc) - 1] = param;
    }

    va_end(params);

    if (rc)
        return rc;

non_va:
    for (int i = idx ? *idx : 0; i < argc; i++) {
        char *param = argv[i];
        const char *value = strstr(param, "=");

        if (!value || value[1] == '\0')
            break;

        if (paramc && paramv) {
            (*paramc)++;
            *paramv = realloc(*paramv, (*paramc) * sizeof(char *));
            if (!*paramv)
                return ENOMEM;
            (*paramv)[(*paramc) - 1] = param;
        }

        if (idx)
            (*idx)++;
    }

    return rc;
}
