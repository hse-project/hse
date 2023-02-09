/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cjson/cJSON.h>

#include <hse/cli/tprint.h>
#include <hse/error/merr.h>
#include <hse/util/assert.h>
#include <hse/util/compiler.h>

#include "utils.h"

#pragma GCC visibility push(default)

const char *kvs_cn_tree_get_headers[] = {
    "T",     "NODE",  "IDX",   "DGEN",  "COMP",  "KEYS",  "TOMBS", "PTOMBS", "HWLEN",
    "KWLEN", "VWLEN", "VGARB", "HBLKS", "KBLKS", "VBLKS", "VGRPS", "RULE",   "STATE...",
};

#define NUM_HEADERS (sizeof(kvs_cn_tree_get_headers) / sizeof(kvs_cn_tree_get_headers[0]))

size_t kvs_cn_tree_get_columnc = NUM_HEADERS;

enum tprint_justify kvs_cn_tree_get_justify[NUM_HEADERS] = {
    TP_JUSTIFY_LEFT,  TP_JUSTIFY_RIGHT, TP_JUSTIFY_RIGHT, TP_JUSTIFY_RIGHT, TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_RIGHT, TP_JUSTIFY_RIGHT, TP_JUSTIFY_RIGHT, TP_JUSTIFY_RIGHT, TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_RIGHT, TP_JUSTIFY_RIGHT, TP_JUSTIFY_RIGHT, TP_JUSTIFY_RIGHT, TP_JUSTIFY_RIGHT,
    TP_JUSTIFY_RIGHT, TP_JUSTIFY_RIGHT, TP_JUSTIFY_LEFT,
};

/* strv_base[] is an easily extensible list of common strings used
 * to build the tabular output array.  It helps reduce the number
 * of calls to malloc/free, and simplifies the task of detecting
 * that these strings must not be freed.
 *
 * The alignment of strv_base[] must be a power-of-two greater than
 * or equal to its size in order for strv_contains() to work properly.
 */
static char strv_base[] HSE_ALIGNED(16) = { 'k', '\000', 'n', '\000', 't',   '\000',
                                            '-', '\000', '-', '\n',   '\000' };

/* Named constant strings from strv_base[] for use
 * in building the tabular output array.
 */
static char * const strv_kvset = strv_base;
static char * const strv_node = strv_base + 2;
static char * const strv_tree = strv_base + 4;
static char * const strv_dash = strv_base + 6;
static char * const strv_dashnl = strv_base + 8;

static inline bool
strv_contains(void *addr)
{
    const uintptr_t mask = __alignof__(strv_base) - 1;

    /* Return true it addr resides within strv_base[].
     */
    return ((uintptr_t)addr & ~mask) == (uintptr_t)strv_base;
}

static merr_t
parse_common(char ** const values, cJSON * const elem, unsigned int * const offset)
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

    item = cJSON_GetObjectItemCaseSensitive(elem, "keys");
    assert(cJSON_IsNumber(item) || cJSON_IsString(item));
    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;

    item = cJSON_GetObjectItemCaseSensitive(elem, "tombs");
    assert(cJSON_IsNumber(item) || cJSON_IsString(item));
    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;

    item = cJSON_GetObjectItemCaseSensitive(elem, "ptombs");
    assert(cJSON_IsNumber(item) || cJSON_IsString(item));
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

    item = cJSON_GetObjectItemCaseSensitive(elem, "vgarb");
    assert(cJSON_IsNumber(item) || cJSON_IsString(item));
    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;

    item = cJSON_GetObjectItemCaseSensitive(elem, "hblocks");
    assert(cJSON_IsNumber(item));
    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;

    item = cJSON_GetObjectItemCaseSensitive(elem, "kblocks");
    assert(cJSON_IsNumber(item));
    values[*offset] = rawify(item);
    if (!values[*offset])
        return merr(ENOMEM);
    *offset += 1;

    item = cJSON_GetObjectItemCaseSensitive(elem, "vblocks");
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

    return 0;
}

void
kvs_cn_tree_get_free_values(const int len, char ** const values)
{
    if (len < 1 || !values)
        return;

    assert(kvs_cn_tree_get_columnc < SIZE_MAX / len);

    for (size_t n = 0; n < kvs_cn_tree_get_columnc * len; ++n) {
        if (!strv_contains(values[n]))
            free(values[n]);
    }

    free(values);
}

/* This function is called to produce a tabular representation of the tree
 * from the JSON produced by cn_tree_serialize() in cn.c.  There are no
 * direct callers of this function.  Instead, it is invoked through function
 * pointers obtained via dlsym() by setup_tabular_custom().
 */
merr_t
kvs_cn_tree_get_parse_values(cJSON * const body, int * const len, char *** const values)
{
    merr_t err;
    char buf[128];
    uint64_t cnid = 0;
    double samp_curr = 0;
    cJSON *nodes, *entry;
    int rc HSE_MAYBE_UNUSED;
    unsigned int prev_kvsetc = 0;
    unsigned int offset = 0, nodec = 0, tree_kvsetc = 0, node_kvsetc = 0;

    INVARIANT(cJSON_IsObject(body));
    INVARIANT(values);

    *len = 0;
    *values = NULL;

    /* One for the tree */
    *len = 1;

    nodes = cJSON_GetObjectItemCaseSensitive(body, "nodes");
    assert(cJSON_IsArray(nodes));

    for (cJSON *n = nodes->child; n; n = n->next, (*len)++) {
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
        uint idx = 0;
        cJSON *kvsets, *id;

        kvsets = cJSON_GetObjectItemCaseSensitive(n, "kvsets");
        assert(cJSON_IsNumber(kvsets) || cJSON_IsArray(kvsets));

        id = cJSON_GetObjectItemCaseSensitive(n, "id");
        assert(cJSON_IsNumber(id));

        if (cJSON_IsArray(kvsets)) {
            node_kvsetc = cJSON_GetArraySize(kvsets);

            /* If either this node or the previous node contained one
             * or more kvsets then append a newline to the edge key
             * of the previous node.
             */
            if ((node_kvsetc > 0 || prev_kvsetc > 0) && offset > 0) {
                char *addr = (*values)[offset - 1];

                if (strv_contains(addr)) {
                    (*values)[offset - 1] = strv_dashnl;
                } else {
                    size_t len = strlen(addr);

                    /* rawify() ensures there is sufficent space
                     * to append a newline.
                     */
                    addr[len++] = '\n';
                    addr[len] = '\000';
                }
            }

            prev_kvsetc = node_kvsetc;

            for (cJSON *k = kvsets ? kvsets->child : NULL; k; k = k->next) {
                cJSON *job;

                (*values)[offset] = strv_kvset;
                offset += 1;

                (*values)[offset] = rawify(id);
                if (!(*values)[offset])
                    return merr(ENOMEM);
                offset += 1;

                rc = snprintf(buf, sizeof(buf), "%u", idx++);
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

                job = cJSON_GetObjectItemCaseSensitive(k, "job");
                if (cJSON_IsObject(job)) {
                    uint id, progress;
                    ulong time;
                    const char *rule;
                    const char *wmesg;
                    const char *action;

                    entry = cJSON_GetObjectItemCaseSensitive(job, "id");
                    assert(cJSON_IsNumber(entry));
                    id = cJSON_GetNumberValue(entry);

                    entry = cJSON_GetObjectItemCaseSensitive(job, "action");
                    assert(cJSON_IsString(entry));
                    action = cJSON_GetStringValue(entry);

                    entry = cJSON_GetObjectItemCaseSensitive(job, "rule");
                    assert(cJSON_IsString(entry));
                    rule = cJSON_GetStringValue(entry);

                    entry = cJSON_GetObjectItemCaseSensitive(job, "wmesg");
                    assert(cJSON_IsString(entry));
                    wmesg = cJSON_GetStringValue(entry);

                    entry = cJSON_GetObjectItemCaseSensitive(job, "progress");
                    assert(cJSON_IsNumber(entry));
                    progress = cJSON_GetNumberValue(entry);

                    entry = cJSON_GetObjectItemCaseSensitive(job, "time");
                    assert(cJSON_IsNumber(entry));
                    time = cJSON_GetNumberValue(entry);

                    rc = snprintf(
                        buf, sizeof(buf), "- %u %s,%s %s %u%% %lu:%02lu", id, action, rule, wmesg,
                        progress, (time / 60) % 60, time % 60);
                    assert(rc > 0);
                    (*values)[offset] = strdup(buf);
                    if (!(*values)[offset])
                        return merr(ENOMEM);
                } else {
                    assert(cJSON_IsNull(job));
                    (*values)[offset] = strv_dash;
                }
                offset += 1;
            }
        } else {
            node_kvsetc = cJSON_GetNumberValue(kvsets);
            prev_kvsetc = 0;
        }

        (*values)[offset] = strv_node;
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

        (*values)[offset] = strv_dash;
        offset += 1;

        entry = cJSON_GetObjectItemCaseSensitive(n, "edge_key");
        assert(cJSON_IsString(entry) || cJSON_IsNull(entry));
        (*values)[offset] = cJSON_IsString(entry) ? rawify(entry) : strv_dash;
        if (!(*values)[offset])
            return merr(ENOMEM);
        offset += 1;

        tree_kvsetc += node_kvsetc;
        nodec++;
    }

    /* If the previous node contained one or more kvsets then append
     * a newline to the edge key of the previous node.
     */
    if (prev_kvsetc > 0 && offset > 0) {
        char *addr = (*values)[offset - 1];

        if (strv_contains(addr)) {
            (*values)[offset - 1] = strv_dashnl;
        } else {
            size_t len = strlen(addr);

            /* rawify() ensures there is sufficent space to append a newline. */
            addr[len++] = '\n';
            addr[len] = '\000';
        }
    }

    (*values)[offset] = strv_tree;
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

    (*values)[offset] = strv_dash;
    offset += 1;

    (*values)[offset] = NULL;

    entry = cJSON_GetObjectItemCaseSensitive(body, "cnid");
    if (cJSON_IsNumber(entry))
        cnid = cJSON_GetNumberValue(entry);

    entry = cJSON_GetObjectItemCaseSensitive(body, "samp_curr");
    if (cJSON_IsNumber(entry))
        samp_curr = cJSON_GetNumberValue(entry);

    entry = cJSON_GetObjectItemCaseSensitive(body, "name");
    assert(cJSON_IsString(entry));

    rc = snprintf(
        buf, sizeof(buf), "- %lu %s %.3lf", cnid, cJSON_GetStringValue(entry), samp_curr / 1000);
    assert(rc > 0);
    (*values)[offset] = strdup(buf);
    if (!(*values)[offset])
        return merr(ENOMEM);
    offset += 1;

    return 0;
}

#pragma GCC visibility pop
