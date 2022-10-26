/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc. All rights reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <bsd/string.h>
#include <cjson/cJSON.h>

#include <hse/error/merr.h>

#include <hse/util/assert.h>

merr_t
flatten(cJSON *const in, const char *const prefix, cJSON *const out)
{
    merr_t err = 0;
    char *tmp = NULL;

    INVARIANT(in);
    INVARIANT(cJSON_IsObject(out));

    if (!cJSON_IsObject(in))
        return 0;

    for (cJSON *n = in->child; n; n = n->next) {
        const size_t len = (prefix ? strlen(prefix) : 0) + strlen(n->string) + 2;

        tmp = malloc(len);
        if (!tmp)
            return merr(ENOMEM);

        if (!prefix || strlen(prefix) == 0) {
            strlcpy(tmp, n->string, len);
        } else {
            snprintf(tmp, len, "%s.%s", prefix, n->string);
        }

        err = flatten(n, tmp, out);
        if (err)
            goto end;

        if (cJSON_IsObject(n))
            goto end;

        if (!cJSON_AddItemToObject(out, tmp, cJSON_Duplicate(n, cJSON_False))) {
            err = merr(ENOMEM);
            goto out;
        }

    end:
        free(tmp);

        if (err)
            goto out;
    }

out:
    return err;
}

char *
rawify(cJSON *const node)
{
    char *printed;
    size_t len;

    printed = cJSON_PrintUnformatted(node);

    if (cJSON_IsString(node)) {
        len = strlen(printed) - 2;

        /* Remove double quote from each end.
         */
        memmove(printed, printed + 1, len);
        printed[len] = '\000';
    }

    return printed;
}

unsigned int
strchrrep(char *const str, const char old, const char new)
{
    char *ix = str;
    unsigned int n = 0;

    if (!str)
        return 0;

    while((ix = strchr(ix, old))) {
        *ix++ = new;
        n++;
    }

    return n;
}
