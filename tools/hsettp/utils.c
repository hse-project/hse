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

#include <hse_util/assert.h>

merr_t
flatten(cJSON *const in, const char *const prefix, cJSON *const out)
{
    merr_t err;
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
    char *data;
    char *printed;
    size_t printed_len;

    if (!cJSON_IsString(node))
        return cJSON_PrintUnformatted(node);

    printed = cJSON_PrintUnformatted(node);
    printed_len = strlen(printed) - 1;

    data = malloc(printed_len * sizeof(*data));
    if (!data) {
        cJSON_free(printed);
        return NULL;
    }

    strlcpy(data, printed + 1, printed_len);

    free(printed);

    return data;
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
