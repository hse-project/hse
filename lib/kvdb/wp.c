/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/* [HSE_REVISIT] - This is a massive layering violation */

#include <hse/hse.h>
#include <hse/hse_experimental.h>

#include <hse_util/param.h>
#include <hse_util/slab.h>
#include <hse_util/string.h>
#include <hse_util/event_counter.h>

#include <hse_ikvdb/wp.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/mclass_policy.h>

#include <yaml.h>

#define WP_VALIDATE_NONE(key, req)               \
    {                                            \
        key, 0, *wp_parser_validate_none, req, 0 \
    }

#define WP_VALIDATE_GENERIC(key, func, req) \
    {                                       \
        key, 0, *func, req, 0               \
    }

/* libYAML Basics
 *
 * Documents in libYAML support scalar, sequence, and mapping nodes.
 * Scalar nodes store values in node->data.value.scalar. Sequence nodes
 * store items in node->data.sequence.items. Mapping nodes store key-value
 * pairs in node->data.mapping.pairs. Each item in a sequence will point
 * to a single node, while each pair in a map will point to two nodes.
 * The nodes in a pair can be referenced with pair->key and pair->value.
 * Note that items and pairs are organized as a stack. To iterate, use
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
 * @wpv_exact:     exact match required
 * @wpv_count:     internal counter (initialized to zero)
 */
struct wp_validation {
    char *wpv_key;
    int   wpv_offset;
    merr_t (*wpv_invalid)(struct hse_params *, yaml_document_t *, yaml_node_t *, char *);
    bool wpv_exact;
    int  wpv_count;
};

/**
 * struct mclass_validation - media class field validation
 * @mc_count:    internal counter (initialized to zero)
 * @mc_ntype:    expected yaml node type
 * @mc_nentries: number of entries in mc_maps
 * @mc_maps:     array of valid match entries for this field
 */
struct mclass_validation {
    int                             mc_count;
    yaml_node_type_t                mc_ntype;
    int                             mc_nmatches;
    const struct mclass_policy_map *mc_maps;
};

char last_map[128];

/* Parser Helper Functions */

static yaml_node_pair_t *
wp_parser_find_field(yaml_document_t *doc, yaml_node_t *node, char *field)
{
    int               match;
    yaml_node_t *     key;
    yaml_node_pair_t *start;
    yaml_node_pair_t *top;

    if (node->type != YAML_MAPPING_NODE)
        return NULL;

    start = node->data.mapping.pairs.start;
    top = node->data.mapping.pairs.top;

    for (; start < top; start++) {
        key = yaml_document_get_node(doc, start->key);
        if (!key)
            continue;

        match = !strcmp(field, (const char *)key->data.scalar.value);
        if (match)
            return start;
    }

    return NULL;
}

static int
wp_parser_get_api_version(struct hse_params *params, yaml_document_t *doc, yaml_node_t *root)
{
    yaml_node_pair_t *node;
    yaml_node_t *     value;

    node = wp_parser_find_field(doc, root, "api_version");
    if (!node) {
        node = wp_parser_find_field(doc, root, "apiVersion");
        if (!node)
            return -1;
    }

    value = yaml_document_get_node(doc, node->value);
    if (!value)
        return -1;

    return atoi((const char *)value->data.scalar.value);
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
        hse_log(HSE_ERR "wp_parser: incomplete key-value pair");
        return merr(EINVAL);
    }

    if (ev(strlcpy(last_map, (const char *)key->data.scalar.value, sizeof(last_map)) >=
           sizeof(last_map)))
        return merr(EINVAL);

    for (i = 0; i < entries; i++) {
        const char *kname = (const char *)key->data.scalar.value;

        field = valid_fields[i].wpv_key;
        match = !strcmp(field, kname);

        /* Some keys like kvs can be a partial match (kvs.SomeKvs) */
        if (!match && !valid_fields[i].wpv_exact) {
            int len = strlen(valid_fields[i].wpv_key);

            if (strlen(kname) > len)
                match = !strncmp(field, kname, len);
        }

        if (match) {
            if (ev(valid_fields[i].wpv_count && valid_fields[i].wpv_exact)) {
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
        hse_log(HSE_ERR "wp_parser: unrecognized key [%s]", key->data.scalar.value);
        return merr(EINVAL);
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

        if (ev(!key || !value)) {
            hse_log(HSE_ERR "wp_parser: incomplete key-value pair");
            return 0;
        }

        snprintf(buf, sizeof(buf), "%s.%s", last_map, (const char *)key->data.scalar.value);

        if (hse_params_set(params, buf, (const char *)value->data.scalar.value)) {
            hse_log(
                HSE_ERR "wp_parser: invalid key [%s] or value [%s]", buf, value->data.scalar.value);
            return 0;
        }
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
wp_parser_encode_mclass_field(
    yaml_node_t *             key,
    struct mclass_validation *fields,
    int                       lvl,
    char *                    prefix,
    int                       prefix_len)
{
    char str[11];
    int  i;

    for (i = 0; i < fields[lvl].mc_nmatches; i++) {
        if (!strcasecmp((const char *)key->data.scalar.value, fields[lvl].mc_maps[i].mc_kname)) {

            if (ev(snprintf(str, sizeof(str), "%d", fields[lvl].mc_maps[i].mc_enum) >= sizeof(str)))
                return merr(EINVAL);

            if (ev(strlcat(prefix, str, prefix_len) >= prefix_len))
                return merr(EINVAL);
            break;
        }
    }

    if (ev(i == fields[lvl].mc_nmatches)) {
        hse_log(HSE_ERR "wp_parser: invalid key [%s%s]", prefix, key->data.scalar.value);
        return merr(EINVAL);
    }

    return 0;
}

static merr_t
wp_parser_validate_mclass_field(
    yaml_document_t *         doc,
    yaml_node_t *             node,
    struct mclass_validation *fields,
    int                       lvl,
    char *                    parent,
    char *                    valbuf,
    int                       valbuf_len)
{
    char   prefix[10];
    merr_t err = 0;

    if (ev(node->type != fields[lvl].mc_ntype))
        return merr(EINVAL);

    if (node->type == YAML_MAPPING_NODE) {
        yaml_node_pair_t *start;
        yaml_node_pair_t *top;

        start = node->data.mapping.pairs.start;
        top = node->data.mapping.pairs.top;

        for (; start < top; start++) {
            yaml_node_t *key;
            yaml_node_t *value;

            key = yaml_document_get_node(doc, start->key);
            value = yaml_document_get_node(doc, start->value);

            if (ev(!key || !value)) {
                hse_log(HSE_ERR "wp_parser: incomplete key-value pair");
                return merr(EINVAL);
            }

            if (ev(strlcpy(prefix, parent, sizeof(prefix)) >= sizeof(prefix)))
                return merr(EINVAL);

            err = wp_parser_encode_mclass_field(key, fields, lvl, prefix, sizeof(prefix));
            if (ev(err))
                return err;

            if (ev(strlcat(prefix, ".", sizeof(prefix)) >= sizeof(prefix)))
                return merr(EINVAL);

            err = wp_parser_validate_mclass_field(
                doc, value, fields, lvl + 1, prefix, valbuf, valbuf_len);
            if (ev(err))
                return err;
        }
    } else if (node->type == YAML_SEQUENCE_NODE) {
        yaml_node_item_t *start;
        yaml_node_item_t *top;
        int               index = 0;
        char              str[11];

        start = node->data.sequence.items.start;
        top = node->data.sequence.items.top;

        for (; start < top; start++, index++) {
            yaml_node_t *key;

            key = yaml_document_get_node(doc, *start);
            if (ev(!key)) {
                hse_log(HSE_ERR "wp_parser: missing node [%s]", prefix);
                return merr(EINVAL);
            }

            if (ev(strlcpy(prefix, parent, sizeof(prefix)) >= sizeof(prefix)))
                return merr(EINVAL);

            if (ev(snprintf(str, sizeof(str), "%d", index) >= sizeof(str)))
                return merr(EINVAL);

            if (ev(strlcat(prefix, str, sizeof(prefix)) >= sizeof(prefix)))
                return merr(EINVAL);

            if (strstr(valbuf, prefix)) {
                hse_log(HSE_ERR "wp_parser: duplicate entry for media class setting [%s]", prefix);
                return merr(EINVAL);
            }

            if (ev(strlcat(prefix, "=", sizeof(prefix)) >= sizeof(prefix)))
                return merr(EINVAL);

            err = wp_parser_encode_mclass_field(key, fields, lvl, prefix, sizeof(prefix));
            if (ev(err))
                return err;

            /*
             * Append the current entry in the form:
             * <age.dtype.index=staging> to the value field.
             * Use ';' as a delimiter between entries.
             */
            if (strlen(valbuf)) {
                if (ev(strlcat(valbuf, ";", valbuf_len) >= valbuf_len))
                    return merr(EINVAL);
            }

            if (ev(strlcat(valbuf, prefix, valbuf_len) >= valbuf_len))
                return merr(EINVAL);
        }
    }

    return 0;
}

static merr_t
wp_parser_validate_mclass(
    struct hse_params *params,
    yaml_document_t *  doc,
    yaml_node_t *      node,
    char *             field)
{
    merr_t                    err = 0;
    yaml_node_pair_t *        start;
    yaml_node_pair_t *        top;
    int                       i, count = 0;
    struct mclass_validation *mfields;

    if (ev(node->type != YAML_MAPPING_NODE))
        return merr(EINVAL);

    count = mclass_policy_get_num_fields();
    mfields = calloc(count, sizeof(struct mclass_validation));
    if (!mfields)
        return (ev(ENOMEM));

    for (i = 0; i < count; i++) {
        mfields[i].mc_count = 0;
        mfields[i].mc_nmatches = mclass_policy_get_num_map_entries(i);
        mfields[i].mc_maps = mclass_policy_get_map(i);
        mfields[i].mc_ntype = YAML_MAPPING_NODE;
    }

    mfields[count - 1].mc_ntype = YAML_SEQUENCE_NODE;

    start = node->data.mapping.pairs.start;
    top = node->data.mapping.pairs.top;

    /* Iterate through the media class policies. */
    for (i = 0; start < top; start++, i++) {
        yaml_node_t *key;
        yaml_node_t *value;

        char keybuf[256] = "";
        char valbuf[256] = "";
        char prefix[10] = "";

        key = yaml_document_get_node(doc, start->key);
        value = yaml_document_get_node(doc, start->value);

        if (ev(!key || !value)) {
            hse_log(HSE_ERR "wp_parser: incomplete key-value pair");
            err = merr(EINVAL);
            goto err0;
        }

        err =
            wp_parser_validate_mclass_field(doc, value, mfields, 0, prefix, valbuf, sizeof(valbuf));
        if (ev(err))
            goto err0;

        snprintf(keybuf, sizeof(keybuf), "%s.%s", last_map, (const char *)key->data.scalar.value);

        err = hse_params_set(params, keybuf, (const char *)valbuf);
        if (ev(err)) {
            hse_log(HSE_ERR "wp_parser: invalid key [%s] or value [%s]", keybuf, valbuf);
            goto err0;
        }
    }

err0:
    free(mfields);

    return err;
}

static merr_t
wp_parser_parse_mclass(struct hse_params *params, yaml_document_t *doc, yaml_node_t *root)
{
    yaml_node_pair_t *node;
    merr_t            err;

    struct wp_validation valid_fields[] = {
        WP_VALIDATE_GENERIC("mclass_policies", wp_parser_validate_mclass, true),
    };

    node = wp_parser_find_field(doc, root, "mclass_policies");
    if (!node)
        return 0;

    err = wp_parser_check_pair(params, doc, node, valid_fields, 1);
    if (ev(err))
        return err;

    return 0;
}

static merr_t
wp_parser_validate_root(struct hse_params *params, yaml_document_t *doc, yaml_node_t *node)
{
    int    entries;
    merr_t err;

    /*
     * mclass_policies and api_version sections have already been validated.
     */
    struct wp_validation valid_fields[] = {
        WP_VALIDATE_NONE("api_version", true),
        WP_VALIDATE_NONE("apiVersion", true),
        WP_VALIDATE_GENERIC("kvdb", wp_parser_validate_params, true),
        WP_VALIDATE_GENERIC("kvs", wp_parser_validate_params, false),
        WP_VALIDATE_NONE("mclass_policies", true),
    };

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
        hse_log(HSE_ERR "wp_parser: failed to initialize YAML parser");
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
        hse_log(HSE_ERR "wp_parser: unrecognized flag %d", flag);
        return merr(EINVAL);
    }

    if (ev(!yaml_parser_load(&parser, &doc))) {
        hse_log(HSE_ERR "wp_parser: failed to load YAML parser");
        err = merr(EINVAL);
        goto err2;
    }

    root = yaml_document_get_root_node(&doc);
    if (ev(!root)) {
        hse_log(HSE_ERR "wp_parser: missing root node, "
                        "double-check syntax");
        err = merr(EINVAL);
        goto err1;
    }

    apiVersion = wp_parser_get_api_version(params, &doc, root);
    switch (apiVersion) {
        case 1:
            err = wp_parser_parse_mclass(params, &doc, root);
            if (ev(err)) {
                hse_log(HSE_ERR "wp_parser: failed to parse mclass_policies");
                goto err1;
            }
            err = wp_parser_validate_root(params, &doc, root);
            if (ev(err)) {
                hse_log(HSE_ERR "wp_parser: failed to parse");
                goto err1;
            }
            break;
        default:
            hse_log(HSE_ERR "wp_parser: unrecognized api_version");
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

    err = wp_parser_exec(profile, strlen(profile), params, flag);
    if (ev(err)) {
        err = merr(EINVAL);
        goto err;
    }

    if (flag == WP_FILE)
        hse_log(HSE_NOTICE "wp: successfully applied profile %s", profile);

    return 0;
err:
    if (flag == WP_FILE)
        hse_log(HSE_ERR "wp: failed to apply profile %s", profile);
    else
        hse_log(HSE_ERR "wp: failed to load predefined media class policies");

    return err;
}
