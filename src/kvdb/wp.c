/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/* [HSE_REVISIT] - This is a massive layering violation */

#include <hse/hse.h>

#include <hse_util/param.h>
#include <hse_util/slab.h>
#include <hse_util/event_counter.h>

#include <hse_ikvdb/wp.h>
#include <hse_ikvdb/limits.h>

#include <yaml.h>

#define WP_VALIDATE_NONE(key, req)               \
    {                                            \
        key, 0, *wp_parser_validate_none, req, 0 \
    }

#define WP_VALIDATE_GENERIC(key, func, req) \
    {                                       \
        key, 0, *func, req, 0               \
    }

#define WP_VALIDATE_UNKNOWN(func)       \
    {                                   \
        "__unknown", 0, *func, false, 0 \
    }

/* libYAML Basics
 *
 * Documents in libYAML support scalar, sequence, and mapping nodes.
 * Scalar nodes store values in node->data.value.scalar. Sequence nodes
 * store items in node->data.sequence.items. Mapping nodes store key-value
 * pairs in node->data.mapping.pairs. Each item in a sequence will point
 * to a single node, while each pair in a map will point to two nodes.
 * The nodes in a pair can be referenced with pair->key and pair->value.
 * Note that items and pairs are oragnized as a stack. To iterate, use
 * the provided start and top addresses.
 *
 * To update the parser schema, add a key and a corresponding validation
 * function to valid_fields[]. For nested dictionaries, use the provided
 * wp_parser_iterate_map() helper function.
 */

/* Parser Internal Structures */

/**
 * struct wp_validation - key-value pair validation
 * @wpv_key:       expected key
 * @wpv_offset:    offset address
 * @wpv_invalid:   validation function
 * @wpv_required:  mark as required
 * @wpv_count:     internal counter (initialized to zero)
 */
struct wp_validation {
    char *wpv_key;
    int   wpv_offset;
    merr_t (*wpv_invalid)(struct hse_params *, yaml_document_t *, yaml_node_t *, char *);
    bool wpv_required;
    int  wpv_count;
};

char last_map[128];

/* Parser Helper Functions */

static yaml_node_t *
wp_parser_find_field(yaml_document_t *doc, yaml_node_t *node, char *field)
{
    int               match;
    yaml_node_t *     key;
    yaml_node_t *     value;
    yaml_node_pair_t *start;
    yaml_node_pair_t *top;

    if (node->type != YAML_MAPPING_NODE)
        return NULL;

    start = node->data.mapping.pairs.start;
    top = node->data.mapping.pairs.top;

    for (; start < top; start++) {
        key = yaml_document_get_node(doc, start->key);
        value = yaml_document_get_node(doc, start->value);
        if (!key || !value)
            continue;

        match = !strcmp(field, (const char *)key->data.scalar.value);
        if (match)
            return value;
    }

    return NULL;
}

static int
wp_parser_get_api_version(struct hse_params *params, yaml_document_t *doc, yaml_node_t *root)
{
    yaml_node_t *node;

    node = wp_parser_find_field(doc, root, "apiVersion");
    if (!node)
        return -1;

    return atoi((const char *)node->data.scalar.value);
}

static merr_t
wp_parser_check_pair(
    struct hse_params *   params,
    yaml_document_t *     doc,
    yaml_node_pair_t *    pair,
    struct wp_validation *valid_fields,
    int                   entries)
{
    int          i;
    int          match;
    char *       field;
    yaml_node_t *key;
    yaml_node_t *value;

    key = yaml_document_get_node(doc, pair->key);
    value = yaml_document_get_node(doc, pair->value);

    if (ev(!key || !value)) {
        hse_log(HSE_ERR "wp_parser: incompleted key-value pair");
        return merr(EINVAL);
    }

    strcpy(last_map, (const char *)key->data.scalar.value);

    for (i = 0; i < entries; i++) {
        field = valid_fields[i].wpv_key;

        match = !strcmp(field, (const char *)key->data.scalar.value);
        if (match) {
            if (ev(valid_fields[i].wpv_count)) {
                hse_log(HSE_ERR "wp_parser: duplicate key [%s]", key->data.scalar.value);
                return merr(EINVAL);
            }

            if (ev(valid_fields[i].wpv_invalid(params, doc, value, field))) {
                hse_log(
                    HSE_ERR "wp_parser: invalid value "
                            "for [%s]",
                    key->data.scalar.value);
                return merr(EINVAL);
            }

            valid_fields[i].wpv_count++;
            break;
        }
    }

    if (ev(i == entries)) {
        if (!strcmp(valid_fields[i - 1].wpv_key, "__unknown")) {
            if (ev(valid_fields[i - 1].wpv_invalid(
                    params, doc, value, (char *)key->data.scalar.value))) {
                hse_log(
                    HSE_ERR "wp_parser: invalid value "
                            "for [%s]",
                    key->data.scalar.value);
                return merr(EINVAL);
            }
        } else {
            hse_log(HSE_ERR "wp_parser: unrecognized key [%s]", key->data.scalar.value);
            return merr(EINVAL);
        }
    }

    return 0;
}

static merr_t
wp_parser_iterate_map(
    struct hse_params *   params,
    yaml_document_t *     doc,
    yaml_node_t *         node,
    struct wp_validation *valid_fields,
    int                   entries)
{
    int               i;
    yaml_node_pair_t *start;
    yaml_node_pair_t *top;
    merr_t            err;

    if (ev(node->type != YAML_MAPPING_NODE)) {
        hse_log(HSE_ERR "wp_parser: unable to iterate specified node");
        return merr(EINVAL);
    }

    start = node->data.mapping.pairs.start;
    top = node->data.mapping.pairs.top;

    for (; start < top; start++) {
        err = wp_parser_check_pair(params, doc, start, valid_fields, entries);
        if (ev(err))
            return err;
    }

    for (i = 0; i < entries; i++) {
        if (ev(!valid_fields[i].wpv_count && valid_fields[i].wpv_required)) {
            hse_log(
                HSE_ERR "wp_parser: missing required "
                        "field [%s]",
                valid_fields[i].wpv_key);
            return merr(EINVAL);
        }
        valid_fields[i].wpv_count = 0;
    }

    return 0;
}

static int
wp_parser_set_params(struct hse_params *params, yaml_document_t *doc, yaml_node_t *node)

{
    char              buf[256];
    yaml_node_pair_t *start;
    yaml_node_pair_t *top;
    yaml_node_t *     key;
    yaml_node_t *     value;

    if (node->type != YAML_MAPPING_NODE)
        return 0;

    start = node->data.mapping.pairs.start;
    top = node->data.mapping.pairs.top;

    for (; start < top; start++) {
        key = yaml_document_get_node(doc, start->key);
        value = yaml_document_get_node(doc, start->value);
        if (!key || !value)
            return 0;

        snprintf(buf, sizeof(buf), "%s.%s", last_map, (const char *)key->data.scalar.value);

        if (hse_params_set(params, buf, (const char *)value->data.scalar.value))
            return 0;
    }

    return -1;
}

static merr_t
wp_parser_validate_none(
    struct hse_params *params,
    yaml_document_t *  doc,
    yaml_node_t *      node,
    char *             field)
{
    return 0;
}

static merr_t
wp_parser_validate_params(
    struct hse_params *params,
    yaml_document_t *  doc,
    yaml_node_t *      node,
    char *             field)
{
    if (ev(node->type != YAML_MAPPING_NODE))
        return merr(EINVAL);

    if (ev(!wp_parser_set_params(params, doc, node)))
        return merr(EINVAL);

    return 0;
}

static merr_t
wp_parser_validate_root(struct hse_params *params, yaml_document_t *doc, yaml_node_t *node)
{
    int    entries;
    merr_t err;

    struct wp_validation valid_fields[] = { WP_VALIDATE_NONE("apiVersion", true),
                                            WP_VALIDATE_GENERIC(
                                                "kvdb", wp_parser_validate_params, false),
                                            WP_VALIDATE_UNKNOWN(wp_parser_validate_params) };

    if (ev(node->type != YAML_MAPPING_NODE))
        return merr(EINVAL);

    entries = sizeof(valid_fields) / sizeof(valid_fields[0]);

    err = wp_parser_iterate_map(params, doc, node, valid_fields, entries);
    if (ev(err))
        return err;

    return 0;
}

/* Parser */

static merr_t
wp_parser_exec(const char *profile, size_t size, struct hse_params *params, int flag)
{
    FILE *          fp = NULL;
    yaml_document_t doc;
    yaml_node_t *   root;
    yaml_parser_t   parser;
    int             apiVersion;
    merr_t          err;

    if (ev(!params)) {
        hse_log(HSE_ERR "wp_parser: invalid hse params");
        return merr(EINVAL);
    }

    if (ev(!yaml_parser_initialize(&parser))) {
        hse_log(
            HSE_ERR "wp_parser: failed to "
                    "initialize YAML parser for %s",
            profile);
        err = merr(EINVAL);
        goto err3;
    }

    if (flag == WP_STRING) {
        yaml_parser_set_input_string(&parser, (const unsigned char *)profile, size);
    } else if (flag == WP_FILE) {
        fp = fopen(profile, "r");
        if (ev(!fp)) {
            hse_log(HSE_ERR "wp_parser: unable to open %s", profile);
            return merr(EINVAL);
        }
        yaml_parser_set_input_file(&parser, fp);
    } else {
        hse_log(HSE_ERR "wp_parser: unable to open %s", profile);
        return merr(EINVAL);
    }

    if (ev(!yaml_parser_load(&parser, &doc))) {
        hse_log(
            HSE_ERR "wp_parser: failed to "
                    "load YAML parser for %s",
            profile);
        err = merr(EINVAL);
        goto err2;
    }

    root = yaml_document_get_root_node(&doc);
    if (ev(!root)) {
        hse_log(
            HSE_ERR "wp_parser: missing root node, "
                    "double-check syntax in %s",
            profile);
        err = merr(EINVAL);
        goto err1;
    }

    apiVersion = wp_parser_get_api_version(params, &doc, root);
    switch (apiVersion) {
        case 1:
            err = wp_parser_validate_root(params, &doc, root);
            if (ev(err)) {
                hse_log(
                    HSE_ERR "wp_parser: failed to "
                            "parse %s",
                    profile);
                goto err1;
            }
            break;
        default:
            hse_log(
                HSE_ERR "wp_parser: unrecognized apiVersion "
                        "in %s",
                profile);
            err = merr(EINVAL);
            goto err1;
    }

err1:
    yaml_document_delete(&doc);
err2:
    yaml_parser_delete(&parser);
err3:
    if (fp)
        fclose(fp);

    return err;
}

/* Exposed API */
merr_t
wp_parse(const char *profile, struct hse_params *params, int flag)
{
    merr_t err;

    err = wp_parser_exec(profile, strlen(profile), params, WP_FILE);
    if (ev(err)) {
        err = merr(EINVAL);
        goto err;
    }

    hse_log(HSE_NOTICE "wp: successfully applied profile %s", profile);

    return 0;
err:
    hse_log(HSE_ERR "wp: failed to apply profile %s", profile);
    return err;
}
