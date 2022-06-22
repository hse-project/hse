/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cjson/cJSON.h>

#include <hse/cli/tprint.h>
#include <hse/error/merr.h>
#include <hse_util/assert.h>
#include <hse_util/compiler.h>

#include "utils.h"

#define IGNORE_ME "-"

#pragma GCC visibility push(default)

const char *kvs_cn_tree_get_headers[] = {
    "T", /* If this index moves, change the free func */
    "NODE",
    "KVSET",
    "DGEN",
    "COMPC",
    "VGRPS",
    "KEYS",
    "TOMBS",
    "PTOMBS",
    "HLEN",
    "KLEN",
    "VLEN",
    "HBLKS",
    "KBLKS",
    "VBLKS",
    "RULE", /* If this index moves, change the free func */
    "EKEY",
};

#define NUM_HEADERS (sizeof(kvs_cn_tree_get_headers) / sizeof(kvs_cn_tree_get_headers[0]))

size_t kvs_cn_tree_get_columnc = NUM_HEADERS;

enum tprint_justify kvs_cn_tree_get_justify[NUM_HEADERS] = {
    TP_JUSTIFY_LEFT,
    TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_LEFT,
    TP_JUSTIFY_LEFT,
};

static merr_t
parse_common(
    char **const values,
    cJSON *const elem,
    unsigned int *const offset)
{
    cJSON *item;

    item = cJSON_GetObjectItemCaseSensitive(elem, "dgen");
    assert(cJSON_IsNumber(item));
    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;

    item = cJSON_GetObjectItemCaseSensitive(elem, "compc");
    assert(cJSON_IsNumber(item));
    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;

    item = cJSON_GetObjectItemCaseSensitive(elem, "vgroups");
    assert(cJSON_IsNumber(item));
    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;

    item = cJSON_GetObjectItemCaseSensitive(elem, "keys");
    assert(cJSON_IsNumber(item));
    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;

    item = cJSON_GetObjectItemCaseSensitive(elem, "tombs");
    assert(cJSON_IsNumber(item));
    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;
    item = cJSON_GetObjectItemCaseSensitive(elem, "ptombs");
    assert(cJSON_IsNumber(item));

    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;

    item = cJSON_GetObjectItemCaseSensitive(elem, "hlen");
    assert(cJSON_IsNumber(item) || cJSON_IsString(item));
    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;

    item = cJSON_GetObjectItemCaseSensitive(elem, "klen");
    assert(cJSON_IsNumber(item) || cJSON_IsString(item));
    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;

    item = cJSON_GetObjectItemCaseSensitive(elem, "vlen");
    assert(cJSON_IsNumber(item) || cJSON_IsString(item));
    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;

    item = cJSON_GetObjectItemCaseSensitive(elem, "hblks");
    assert(cJSON_IsNumber(item));
    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;

    item = cJSON_GetObjectItemCaseSensitive(elem, "kblks");
    assert(cJSON_IsNumber(item));
    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;

    item = cJSON_GetObjectItemCaseSensitive(elem, "vblks");
    assert(cJSON_IsNumber(item));
    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;

    return 0;
}

void
kvs_cn_tree_get_free_values(const int len, char **const values)
{
    if (!values)
        return;

    for (int row = 0; row < len; row++) {
        /* First column is a pointer to a ROM string. DO NOT FREE. */
        for (size_t col = 1; col < kvs_cn_tree_get_columnc; col++) {
            if ((col == 15 || col == 16) &&
                    strcmp(values[row * kvs_cn_tree_get_columnc + col], IGNORE_ME) == 0)
                continue;

            free(values[row * kvs_cn_tree_get_columnc + col]);
        }
    }

    free(values);
}

merr_t
kvs_cn_tree_get_parse_values(cJSON *const body, int *const len, char ***const values)
{
    int rc HSE_MAYBE_UNUSED;
    merr_t err;
    cJSON *nodes;
    char buf[128];
    unsigned int offset = 0, nodec = 0, tree_kvsetc = 0, node_kvsetc = 0;

    INVARIANT(cJSON_IsObject(body));
    INVARIANT(values);

    *len = 0;
    *values = NULL;

    /* One for the tree */
    *len = 1;

    nodes = cJSON_GetObjectItemCaseSensitive(body, "nodes");
    assert(cJSON_IsArray(nodes));

    for (cJSON *n = nodes->child; n; n = n->next, (*len)++, nodec++) {
        cJSON *kvsets;

        kvsets = cJSON_GetObjectItemCaseSensitive(n, "kvsets");
        assert(cJSON_IsNumber(kvsets) || cJSON_IsArray(kvsets));

        if (cJSON_IsArray(kvsets))
            (*len) += cJSON_GetArraySize(kvsets);
    }

    *values = calloc(1, *len * kvs_cn_tree_get_columnc * sizeof(**values));
    if (!*values)
        return merr(ENOMEM);

    for (cJSON *n = nodes->child; n; n = n->next) {
        cJSON *kvsets, *id, *entry;

        kvsets = cJSON_GetObjectItemCaseSensitive(n, "kvsets");
        assert(cJSON_IsNumber(kvsets) || cJSON_IsArray(kvsets));

        id = cJSON_GetObjectItemCaseSensitive(n, "id");
        assert(cJSON_IsNumber(id));

        if (cJSON_IsArray(kvsets)) {
            node_kvsetc += cJSON_GetArraySize(kvsets);

            for (cJSON *k = kvsets ? kvsets->child : NULL; k; k = k->next) {
                cJSON *entry;

                (*values)[offset] = "k";
                if (!(*values)[offset])
                    return merr(ENOMEM);
                offset += 1;

                (*values)[offset] = rawify(id);
                if (!(*values)[offset])
                    return merr(ENOMEM);
                offset += 1;

                rc = snprintf(buf, sizeof(buf), "%u", node_kvsetc);
                assert(rc <= sizeof(buf) && rc > 0);
                (*values)[offset] = strdup(buf);
                if (!(*values)[offset])
                    return merr(ENOMEM);
                offset += 1;

                err = parse_common(*values, k, &offset);
                if (err)
                    return err;

                entry = cJSON_GetObjectItemCaseSensitive(k, "rule");
                assert(cJSON_IsString(entry));
                (*values)[offset] = rawify(entry);
                if (!(*values)[offset])
                    return merr(ENOMEM);
                offset += 1;

                (*values)[offset] = IGNORE_ME;
                offset += 1;
            }
        } else {
            node_kvsetc += cJSON_GetNumberValue(kvsets);
        }

        (*values)[offset] = "n";
        if (!(*values)[offset])
            return merr(ENOMEM);
        offset += 1;

        (*values)[offset] = rawify(id);
            if (!(*values)[offset])
                return merr(ENOMEM);
            offset += 1;

        rc = snprintf(buf, sizeof(buf), "%u", node_kvsetc);
        assert(rc <= sizeof(buf) && rc > 0);
        (*values)[offset] = strdup(buf);
        if (!(*values)[offset])
            return merr(ENOMEM);
        offset += 1;

        err = parse_common(*values, n, &offset);
        if (err)
            return err;

        (*values)[offset] = IGNORE_ME;
        offset += 1;

        entry = cJSON_GetObjectItemCaseSensitive(n, "edge_key");
        assert(cJSON_IsString(entry) || cJSON_IsNull(entry));
        (*values)[offset] = cJSON_IsString(entry) ? rawify(entry) : IGNORE_ME;
        if (!(*values)[offset])
            return merr(ENOMEM);
        offset += 1;

        tree_kvsetc += node_kvsetc;
    }

    (*values)[offset] = "t";
    if (!(*values)[offset])
        return merr(ENOMEM);
    offset += 1;

    rc = snprintf(buf, sizeof(buf), "%u", nodec);
    assert(rc <= sizeof(buf) && rc > 0);
    (*values)[offset] = strdup(buf);
    if (!(*values)[offset])
        return merr(ENOMEM);
    offset += 1;

    rc = snprintf(buf, sizeof(buf), "%u", tree_kvsetc);
    assert(rc <= sizeof(buf) && rc > 0);
    (*values)[offset] = strdup(buf);
    if (!(*values)[offset])
        return merr(ENOMEM);
    offset += 1;

    err = parse_common(*values, body, &offset);
    if (err)
        return err;

    (*values)[offset] = IGNORE_ME;
    offset += 1;

    (*values)[offset] = IGNORE_ME;
    offset += 1;

    return 0;
}

#pragma GCC visibility pop
