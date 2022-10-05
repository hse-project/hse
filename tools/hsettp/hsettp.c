/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <bsd/string.h>
#include <cjson/cJSON.h>
#include <cjson/cJSON_Utils.h>
#include <curl/curl.h>

#include <hse/error/merr.h>
#include <hse/cli/rest/client.h>
#include <hse/cli/tprint.h>
#include <hse_util/assert.h>
#include <hse_util/compiler.h>

#include "buffer.h"
#include "format.h"
#include "openapi.h"
#include "options_map.h"
#include "utils.h"

#define OPERATIONS_MAX 64U
#define QUERY_VALUE_FROM_BOOL(b) ((b) ? "true" : "false")

typedef void (*free_values_t)(int, char **);
typedef merr_t (*parse_values_t)(cJSON *, int *, char ***);

static const struct option program_opts[] = {
    { "help", no_argument, NULL, 'h' },
    { "socket", required_argument, NULL, 's' },
    { 0, 0, 0, 0 },
};

enum tablular_type {
    TABULAR_ARRAY,
    TABULAR_FLATTENED,
    TABULAR_CUSTOM,
};

cJSON *openapi;
struct options_map *options_map;

struct {
    enum format type;
    union {
        struct {
            enum tablular_type type;
            size_t columnc;
            char **headers;
            enum tprint_justify *justify;
            bool *enabled;
            union {
                struct {
                    char **pointers;
                } array;
                struct {
                    free_values_t free_values;
                    parse_values_t parse_values;
                } custom;
            } ext;
        } tab;
    } config;
} output_format = { .type = FORMAT_JSON };

static enum tablular_type
tabular_type_from_string(const char *const type)
{
    if (strcmp(type, "array") == 0) {
        return TABULAR_ARRAY;
    } else if (strcmp(type, "flattened") == 0) {
        return TABULAR_FLATTENED;
    } else if (strcmp(type, "custom") == 0) {
        return TABULAR_CUSTOM;
    } else {
        abort();
    }
}

static void
handle_json(
    const long status,
    const char *const headers,
    const size_t headers_len,
    const char *const output,
    const size_t output_len,
    void *const arg)
{
    INVARIANT(headers);
    INVARIANT(output);

    printf("%.*s\n", (int)output_len, output);
}

static merr_t
handle_tabular(
    const long status,
    const char *const headers,
    size_t headers_len,
    const char *const output,
    size_t output_len,
    void *arg)
{
    cJSON *body;
    int len = 0;
    merr_t err = 0;
    char **values = NULL;

    INVARIANT(headers);
    INVARIANT(output);

    body = cJSON_ParseWithLength(output, output_len);
    if (!body) {
        if (cJSON_GetErrorPtr()) {
            return merr(EBADMSG);
        } else {
            return merr(ENOMEM);
        }
    }

    if (output_format.config.tab.type == TABULAR_FLATTENED) {
        if (cJSON_IsObject(body)) {
            cJSON *flattened;

            flattened = cJSON_CreateObject();
            if (!flattened) {
                err = merr(ENOMEM);
                goto out;
            }

            err = flatten(body, NULL, flattened);
            if (err) {
                cJSON_Delete(flattened);
                goto out;
            }

            len = cJSON_GetArraySize(flattened);

            values = calloc(1, 2 * len * sizeof(*values));
            if (!values) {
                err = merr(ENOMEM);
                goto out;
            }

            for (int i = 0; i < len; i++) {
                cJSON *n = cJSON_GetArrayItem(flattened, i);

                values[i * 2] = n->string;
                values[i * 2 + 1] = rawify(n);
                if (!values[i * 2 + 1]) {
                    cJSON_Delete(flattened);
                    err = merr(ENOMEM);
                    goto out;
                }
            }
        } else if (cJSON_IsArray(body)) {
            len = cJSON_GetArraySize(body);

            values = calloc(1, 2 * len * sizeof(*values));
            if (!values) {
                err = merr(ENOMEM);
                goto out;
            }

            for (int i = 0; i < len; i++) {
                cJSON *elem = cJSON_GetArrayItem(body, i);

                values[i * 2] = elem->string;
                values[i * 2 + 1] = rawify(elem);
                if (!values[i * 2 + 1]) {
                    err = merr(ENOMEM);
                    goto out;
                }
            }
        } else {
            abort();
        }
    } else {
        if (cJSON_IsArray(body)) {
            len = cJSON_GetArraySize(body);

            values = calloc(1, len * output_format.config.tab.columnc * sizeof(*values));
            if (!values) {
                err = merr(ENOMEM);
                goto out;
            }

            for (int r = 0; r < len; r++) {
                cJSON *item = cJSON_GetArrayItem(body, r);

                for (size_t c = 0; c < output_format.config.tab.columnc; c++) {
                    cJSON *value = cJSONUtils_GetPointerCaseSensitive(item,
                        output_format.config.tab.ext.array.pointers[c]);
                    assert(value);

                    values[r * output_format.config.tab.columnc + c] = rawify(value);
                    if (!values[r * output_format.config.tab.columnc + c]) {
                        err = merr(ENOMEM);
                        goto out;
                    }
                }
            }
        } else {
            err = output_format.config.tab.ext.custom.parse_values(body, &len, &values);
            assert(values);
        }
    }

    err = tprint(stdout, len, output_format.config.tab.columnc,
        (const char **)output_format.config.tab.headers, (const char **)values,
        output_format.config.tab.justify, output_format.config.tab.enabled);

out:
    switch (output_format.config.tab.type) {
    case TABULAR_ARRAY:
        for (size_t i = 0; i < len * output_format.config.tab.columnc; i++)
            free(values[i]);
        free(values);
        break;
    case TABULAR_FLATTENED:
        for (int i = 0; i < len; i++)
            free(values[i * 2 + 1]);
        free(values);
        break;
    case TABULAR_CUSTOM:
        output_format.config.tab.ext.custom.free_values(len, values);
        break;
    }

    cJSON_Delete(body);

    return err;
}

static merr_t
handle_plain(
    const long status,
    const char *const headers,
    const size_t headers_len,
    const char *const output,
    const size_t output_len,
    void *const arg)
{
    cJSON *body;
    merr_t err = 0;

    INVARIANT(headers);
    INVARIANT(output);

    body = cJSON_ParseWithLength(output, output_len);
    if (!body) {
        if (cJSON_GetErrorPtr()) {
            return merr(EBADMSG);
        } else {
            return merr(ENOMEM);
        }
    }

    if (cJSON_IsString(body)) {
        printf("%s\n", cJSON_GetStringValue(body));
    } else if (cJSON_IsArray(body)) {
        for (cJSON *b = body->child; b; b = b->next) {
            assert(!cJSON_IsObject(b));

            if (cJSON_IsString(b)) {
                printf("%s\n", cJSON_GetStringValue(b));
            } else {
                char *value = cJSON_PrintUnformatted(b);
                if (!value) {
                    err = merr(ENOMEM);
                    goto out;
                }

                printf("%s\n", value);

                cJSON_free(value);
            }
        }
    } else {
        abort();
    }

out:
    cJSON_Delete(body);

    return err;
}

static merr_t
rest_cb(
    const long status,
    const char *const headers,
    const size_t headers_len,
    const char *const output,
    const size_t output_len,
    void *const arg)
{
    merr_t err = 0;

    INVARIANT(headers);
    INVARIANT(output);

    if (status >= 400)
        return merr(EBADMSG);

    switch (output_format.type) {
    case FORMAT_JSON:
        handle_json(status, headers, headers_len, output, output_len, arg);
        break;
    case FORMAT_TABULAR:
        err = handle_tabular(status, headers, headers_len, output, output_len, arg);
        break;
    case FORMAT_PLAIN:
        err = handle_plain(status, headers, headers_len, output, output_len, arg);
        break;
    case FORMAT_INVALID:
        abort();
    }

    return err;
}

static const char *
capitalized_method(const char *const method)
{
    INVARIANT(method);

    if (strcmp(method, "delete") == 0)
        return "DELETE";

    if (strcmp(method, "get") == 0)
        return "GET";

    if (strcmp(method, "post") == 0)
        return "POST";

    if (strcmp(method, "put") == 0)
        return "PUT";

    abort();
}

static cJSON * HSE_RETURNS_NONNULL
follow_ref(cJSON *const obj)
{
    cJSON *ref;

    if (!obj)
        return obj;

    INVARIANT(cJSON_IsObject(obj));

    ref = cJSON_GetObjectItemCaseSensitive(obj, "$ref");
    if (cJSON_IsString(ref)) {
        /* Iterate past the octothorpe since cJSON seems to not understand it.
         */
        return cJSONUtils_GetPointerCaseSensitive(openapi, cJSON_GetStringValue(ref) + 1);
    }

    return obj;
}

typedef bool (*foreach_operation_fn)(cJSON *path, cJSON *method, void *user_data);

static void
foreach_operation(const foreach_operation_fn fn, void *const user_data)
{
    static const char *const methodsv[] = { "get", "put", "post", "delete" };
    static const size_t methodsc = sizeof(methodsv) / sizeof(methodsv[0]);

    cJSON *paths;

    INVARIANT(fn);

    paths = cJSON_GetObjectItemCaseSensitive(openapi, "paths");
    assert(cJSON_IsObject(paths));

    for (cJSON *p = paths->child; p; p = p->next) {
        for (size_t i = 0; i < methodsc; i++) {
            cJSON *m;

            m = cJSON_GetObjectItemCaseSensitive(p, methodsv[i]);
            if (!m)
                continue;

            if (!fn(p, m, user_data))
                return;
        }
    }
}

struct search_args {
    const char *requested_operation_id;
    cJSON **path;
    cJSON **method;
};

static bool
search(cJSON *const path, cJSON *const method, void *const user_data)
{
    cJSON *operation_id;
    struct search_args *args;

    INVARIANT(cJSON_IsObject(path));
    INVARIANT(cJSON_IsObject(method));
    INVARIANT(user_data);

    args = user_data;

    operation_id = cJSON_GetObjectItemCaseSensitive(method, "operationId");
    assert(cJSON_IsString(operation_id));

    if (strcmp(cJSON_GetStringValue(operation_id), args->requested_operation_id) == 0) {
        *args->path = path;
        *args->method = method;
        return false;
    }

    return true;
}

static bool
find_operation(const char *const requested_operation_id, cJSON **const path, cJSON **const method)
{
    struct search_args args = {
        .requested_operation_id = requested_operation_id,
        .path = path,
        .method = method,
    };

    INVARIANT(requested_operation_id);
    INVARIANT(path);
    INVARIANT(method);

    foreach_operation(search, &args);

    return *args.path && *args.method;
}

struct collect_args {
    unsigned int offset;
    struct {
        const char *operation_id;
        cJSON *path;
        cJSON *method;
    } operations[OPERATIONS_MAX];
};

static bool
collect(cJSON *const path, cJSON *const method, void *const user_data)
{
    cJSON *operation_id;
    struct collect_args *args;

    INVARIANT(cJSON_IsObject(path));
    INVARIANT(cJSON_IsObject(method));
    INVARIANT(user_data);

    args = user_data;

    operation_id = cJSON_GetObjectItemCaseSensitive(method, "operationId");
    assert(cJSON_IsString(operation_id));

    /* Increment OPERATIONS_MAX by grepping for the number of occurances of
     * "operationId" in docs/openapi.json.
     */
    if (args->offset > OPERATIONS_MAX - 1)
        abort();

    args->operations[args->offset].operation_id = cJSON_GetStringValue(operation_id);
    args->operations[args->offset].path = path;
    args->operations[args->offset].method = method;
    args->offset++;

    return true;
}

static void
print_operations(FILE *const output)
{
    struct collect_args args = { .offset = 0 };

    foreach_operation(collect, &args);

    for (unsigned int i = 0; i < args.offset; i++) {
        for (unsigned int j = 0; j < args.offset; j++) {
            if (strcmp(args.operations[i].operation_id, args.operations[j].operation_id) < 0) {
                /* In-place swap because we are cool */

                args.operations[i].operation_id = (const char *)
                    ((uintptr_t)args.operations[i].operation_id ^
                        (uintptr_t)args.operations[j].operation_id);
                args.operations[j].operation_id = (const char *)
                    ((uintptr_t)args.operations[i].operation_id ^
                        (uintptr_t)args.operations[j].operation_id);
                args.operations[i].operation_id = (const char *)
                    ((uintptr_t)args.operations[i].operation_id ^
                        (uintptr_t)args.operations[j].operation_id);

                args.operations[i].path = (cJSON *)
                    ((uintptr_t)args.operations[i].path ^
                        (uintptr_t)args.operations[j].path);
                args.operations[j].path = (cJSON *)
                    ((uintptr_t)args.operations[i].path ^
                        (uintptr_t)args.operations[j].path);
                args.operations[i].path = (cJSON *)
                    ((uintptr_t)args.operations[i].path ^
                        (uintptr_t)args.operations[j].path);

                args.operations[i].method = (cJSON *)
                    ((uintptr_t)args.operations[i].method ^
                        (uintptr_t)args.operations[j].method);
                args.operations[j].method = (cJSON *)
                    ((uintptr_t)args.operations[i].method ^
                        (uintptr_t)args.operations[j].method);
                args.operations[i].method = (cJSON *)
                    ((uintptr_t)args.operations[i].method ^
                        (uintptr_t)args.operations[j].method);
            }
        }
    }

    for (unsigned int i = 0; i < args.offset; i++) {
        cJSON *description;

        description = cJSON_GetObjectItemCaseSensitive(args.operations[i].method, "description");
        assert(cJSON_IsString(description));

        fprintf(output, "\t%s\n", args.operations[i].operation_id);
        fprintf(output, "\t\t%s\n", cJSON_GetStringValue(description));
    }
}

static enum tprint_justify HSE_NONNULL(1)
tprint_justify_from_string(const char *str)
{
    if (strcmp(str, "left") == 0)
        return TP_JUSTIFY_LEFT;

    if (strcmp(str, "right") == 0)
        return TP_JUSTIFY_RIGHT;

    abort();
}

static int
setup_tabular_array(
    const char *const operation_id,
    cJSON *const path,
    cJSON *const method,
    cJSON *const config)
{
    cJSON *columns;

    INVARIANT(operation_id);
    INVARIANT(cJSON_IsObject(path));
    INVARIANT(cJSON_IsObject(method));
    INVARIANT(cJSON_IsObject(config));

    columns = cJSON_GetObjectItemCaseSensitive(config, "columns");
    assert(cJSON_IsObject(columns));

    output_format.config.tab.columnc = cJSON_GetArraySize(columns);
    output_format.config.tab.headers = malloc(
        output_format.config.tab.columnc * sizeof(*output_format.config.tab.headers));
    output_format.config.tab.justify = malloc(
        output_format.config.tab.columnc * sizeof(*output_format.config.tab.justify));
    output_format.config.tab.ext.array.pointers = malloc(
        output_format.config.tab.columnc * sizeof(*output_format.config.tab.ext.array.pointers));
    if (!output_format.config.tab.headers || !output_format.config.tab.justify ||
            !output_format.config.tab.ext.array.pointers) {
        free(output_format.config.tab.headers);
        free(output_format.config.tab.justify);
        free(output_format.config.tab.ext.array.pointers);
        fprintf(stderr, "Failed to allocate memory\n");
        return EX_OSERR;
    }

    for (size_t i = 0; i < output_format.config.tab.columnc; i++) {
        cJSON *column, *pointer, *justify;

        column = cJSON_GetArrayItem(columns, i);
        assert(cJSON_IsObject(column));

        pointer = cJSON_GetObjectItemCaseSensitive(column, "pointer");
        assert(cJSON_IsString(pointer));

        justify = cJSON_GetObjectItemCaseSensitive(column, "justify");
        assert(cJSON_IsString(justify));

        output_format.config.tab.headers[i] = column->string;
        output_format.config.tab.justify[i] = tprint_justify_from_string(
            cJSON_GetStringValue(justify));
        output_format.config.tab.ext.array.pointers[i] = cJSON_GetStringValue(pointer);
    }

    return 0;
}

static int
setup_tabular_flattened(
    const char *const operation_id,
    cJSON *const path,
    cJSON *const method,
    cJSON *const config)
{
    cJSON *columns, *first, *second;

    INVARIANT(operation_id);
    INVARIANT(cJSON_IsObject(path));
    INVARIANT(cJSON_IsObject(method));
    INVARIANT(cJSON_IsObject(config));

    columns = cJSON_GetObjectItemCaseSensitive(config, "columns");
    assert(cJSON_IsArray(columns));

    output_format.config.tab.columnc = cJSON_GetArraySize(columns);
    assert(output_format.config.tab.columnc == 2);
    output_format.config.tab.headers = malloc(
        output_format.config.tab.columnc * sizeof(*output_format.config.tab.headers));
    output_format.config.tab.justify = malloc(
        output_format.config.tab.columnc * sizeof(*output_format.config.tab.justify));
    if (!output_format.config.tab.headers || !output_format.config.tab.justify) {
        free(output_format.config.tab.headers);
        free(output_format.config.tab.justify);
        fprintf(stderr, "Failed to allocate memory\n");
        return EX_OSERR;
    }

    first = cJSON_GetArrayItem(columns, 0);
    second = cJSON_GetArrayItem(columns, 1);
    assert(cJSON_IsString(first));
    assert(cJSON_IsString(second));

    output_format.config.tab.headers[0] = cJSON_GetStringValue(first);
    output_format.config.tab.headers[1] = cJSON_GetStringValue(second);
    output_format.config.tab.justify[0] = TP_JUSTIFY_LEFT;
    output_format.config.tab.justify[1] = TP_JUSTIFY_LEFT;

    return 0;
}

static int
setup_tabular_custom(
    const char *const operation_id,
    cJSON *const path,
    cJSON *const method,
    cJSON *const config)
{
    void *handle;
    char **headers;
    size_t *columnc;
    char symbol[128];
    void *free_values;
    void *parse_values;
    int rc HSE_MAYBE_UNUSED;
    enum tprint_justify *justify;

    INVARIANT(operation_id);
    INVARIANT(cJSON_IsObject(path));
    INVARIANT(cJSON_IsObject(method));
    INVARIANT(!config);

    handle = dlopen(NULL, RTLD_LAZY);
    assert(handle);

    rc = snprintf(symbol, sizeof(symbol), "%s_columnc", operation_id);
    assert(rc < sizeof(symbol) && rc > 0);
    strchrrep(symbol, '-', '_');

    columnc = dlsym(handle, symbol);
    assert(columnc);

    rc = snprintf(symbol, sizeof(symbol), "%s_headers", operation_id);
    assert(rc < sizeof(symbol) && rc > 0);
    strchrrep(symbol, '-', '_');

    headers = dlsym(handle, symbol);
    assert(headers);

    rc = snprintf(symbol, sizeof(symbol), "%s_justify", operation_id);
    assert(rc < sizeof(symbol) && rc > 0);
    strchrrep(symbol, '-', '_');

    justify = dlsym(handle, symbol);
    assert(headers);

    rc = snprintf(symbol, sizeof(symbol), "%s_parse_values", operation_id);
    assert(rc < sizeof(symbol) && rc > 0);
    strchrrep(symbol, '-', '_');

    parse_values = dlsym(handle, symbol);
    assert(parse_values);

    rc = snprintf(symbol, sizeof(symbol), "%s_free_values", operation_id);
    assert(rc < sizeof(symbol) && rc > 0);
    strchrrep(symbol, '-', '_');

    free_values = dlsym(handle, symbol);
    assert(free_values);

    output_format.config.tab.columnc = *columnc;
    output_format.config.tab.headers = headers;
    output_format.config.tab.justify = justify;
    output_format.config.tab.ext.custom.free_values = free_values;
    output_format.config.tab.ext.custom.parse_values = parse_values;

    rc = dlclose(handle);
    assert(rc == 0);

    return 0;
}

static int
evaluate_format_option(
    const char *const operation_id,
    cJSON *const path,
    cJSON *const method,
    const char *const str)
{
    int rc;
    cJSON *x_formats, *format, *config;

    INVARIANT(operation_id);
    INVARIANT(cJSON_IsObject(path));
    INVARIANT(cJSON_IsObject(method));
    INVARIANT(str);

    x_formats = cJSON_GetObjectItemCaseSensitive(method, "x-formats");
    assert(cJSON_IsObject(x_formats));

    format = cJSON_GetObjectItemCaseSensitive(x_formats,
        format_to_string(output_format.type));
    if (!format) {
        fprintf(stderr, "Invalid output format: %s\n", format_to_string(output_format.type));
        return EX_USAGE;
    }

    config = cJSON_GetObjectItemCaseSensitive(format, "config");

    switch (output_format.type) {
    case FORMAT_TABULAR: {
        cJSON *type;

        type = cJSON_GetObjectItemCaseSensitive(format, "type");
        assert(cJSON_IsString(type));

        output_format.config.tab.type = tabular_type_from_string(cJSON_GetStringValue(type));
        switch (output_format.config.tab.type) {
        case TABULAR_ARRAY:
            rc = setup_tabular_array(operation_id, path, method, config);
            break;
        case TABULAR_FLATTENED:
            rc = setup_tabular_flattened(operation_id, path, method, config);
            break;
        case TABULAR_CUSTOM:
            rc = setup_tabular_custom(operation_id, path, method, config);
            break;
        }

        if (rc)
            break;

        output_format.config.tab.enabled = malloc(
            output_format.config.tab.columnc * sizeof(*output_format.config.tab.enabled));
        if (!output_format.config.tab.headers || !output_format.config.tab.enabled) {
            fprintf(stderr, "Failed to allocate memory\n");
            return EX_OSERR;
        }

        /* Default to viewing all columns */
        memset(output_format.config.tab.enabled, 1,
            output_format.config.tab.columnc * sizeof(*output_format.config.tab.enabled));

        rc = format_parse_tabular(str, output_format.config.tab.columnc,
            (const char **)output_format.config.tab.headers, output_format.config.tab.enabled);
        if (rc) {
            fprintf(stderr, "Invalid format string: %s\n", str);
            return EX_USAGE;
        }

        break;
    }
    case FORMAT_JSON:
    case FORMAT_PLAIN:
        break;
    case FORMAT_INVALID:
        abort();
    }

    return 0;
}

enum request_body {
    REQUEST_BODY_REQUIRED,
    REQUEST_BODY_OPTIONAL,
    REQUEST_BODY_EMPTY,
};

static unsigned int
count_operation_arguments(cJSON *const path, cJSON *method, enum request_body *state)
{
    unsigned int count = 0;
    cJSON *parameters, *request_body;

    INVARIANT(cJSON_IsObject(path));
    INVARIANT(cJSON_IsObject(method));
    INVARIANT(state);

    *state = REQUEST_BODY_EMPTY;

    parameters = cJSON_GetObjectItemCaseSensitive(path, "parameters");
    if (!parameters)
        return 0;
    assert(cJSON_IsArray(parameters));

    for (cJSON *p = parameters->child; p; p = p->next) {
        cJSON *parameter, *in;

        assert(cJSON_IsObject(p));

        parameter = follow_ref(p);
        assert(cJSON_IsObject(parameter));
        in = cJSON_GetObjectItemCaseSensitive(parameter, "in");
        assert(cJSON_IsString(in));

        if (strcmp(cJSON_GetStringValue(in), "path") == 0)
            count++;
    }

    request_body = cJSON_GetObjectItemCaseSensitive(method, "requestBody");
    request_body = follow_ref(request_body);
    assert(!request_body || cJSON_IsObject(request_body));
    if (request_body) {
        cJSON *required;

        required = cJSON_GetObjectItemCaseSensitive(request_body, "required");
        assert(cJSON_IsBool(required));

        *state = cJSON_IsTrue(required) ? REQUEST_BODY_REQUIRED : REQUEST_BODY_OPTIONAL;
    }

    return count;
}

static void
operation_usage(
    FILE *const output,
    const char *const operation_id,
    cJSON *const path,
    cJSON *const method)
{
    size_t columnc;
    const char **columnv = NULL;
    enum request_body request_body;
    unsigned int operation_arguments;
    cJSON *description, *x_options, *x_formats;

    INVARIANT(output);
    INVARIANT(operation_id);
    INVARIANT(path);
    INVARIANT(method);

    description = cJSON_GetObjectItemCaseSensitive(method, "description");
    assert(cJSON_IsString(description));

    x_options = cJSON_GetObjectItemCaseSensitive(method, "x-options");
    assert(cJSON_IsArray(x_options));

    operation_arguments = count_operation_arguments(path, method, &request_body);

    fprintf(output, "Usage: hsettp [OPTION]... %s [OPTION]...", operation_id);
    if (operation_arguments > 0) {
        cJSON *parameters;

        parameters = cJSON_GetObjectItemCaseSensitive(path, "parameters");
        assert(cJSON_IsArray(parameters));

        fprintf(output, " ");
        for (cJSON *p = parameters->child; p; p = p->next) {
            cJSON *parameter, *name, *in;

            parameter = follow_ref(p);
            assert(cJSON_IsObject(parameter));

            in = cJSON_GetObjectItemCaseSensitive(parameter, "in");
            assert(cJSON_IsString(in));

            if (strcmp(cJSON_GetStringValue(in), "path") != 0)
                continue;

            name = cJSON_GetObjectItemCaseSensitive(parameter, "name");
            assert(cJSON_IsString(name));

            fprintf(output, "<%s> ", cJSON_GetStringValue(name));
        }
    }

    switch (request_body) {
    case REQUEST_BODY_REQUIRED:
        fprintf(output, "<body>");
        break;
    case REQUEST_BODY_OPTIONAL:
        fprintf(output, "[body]");
        /* fallthrough */
    case REQUEST_BODY_EMPTY:
        break;
    }

    fprintf(output, "\n\n");
    fprintf(output, "REST Endpoint: %s\n\n", path->string);
    fprintf(output, "%s\n\n", cJSON_GetStringValue(description));
    fprintf(output, "Options:\n");
    for (cJSON *o = x_options->child; o; o = o->next) {
        cJSON *option, *shortopt, *longopt, *requires_argument;

        option = follow_ref(o);
        assert(cJSON_IsObject(option));

        shortopt = cJSON_GetObjectItemCaseSensitive(option, "short");
        assert(cJSON_IsString(shortopt));

        longopt = cJSON_GetObjectItemCaseSensitive(option, "long");
        assert(cJSON_IsString(longopt));

        description = cJSON_GetObjectItemCaseSensitive(option, "description");
        assert(cJSON_IsString(description));

        requires_argument = cJSON_GetObjectItemCaseSensitive(option, "requires-argument");

        fprintf(output, "\t-%s, --%s %s\n", cJSON_GetStringValue(shortopt),
            cJSON_GetStringValue(longopt), cJSON_IsTrue(requires_argument) ? "arg" : "");
        fprintf(output, "\t\t%s\n", cJSON_GetStringValue(description));
    }

    if (operation_arguments > 0) {
        cJSON *parameters;

        parameters = cJSON_GetObjectItemCaseSensitive(path, "parameters");
        assert(cJSON_IsArray(parameters));

        fprintf(output, "\nArguments:\n");
        for (cJSON *p = parameters->child; p; p = p->next) {
            cJSON *parameter, *name, *in;

            parameter = follow_ref(p);
            assert(cJSON_IsObject(parameter));

            in = cJSON_GetObjectItemCaseSensitive(parameter, "in");
            assert(cJSON_IsString(in));

            if (strcmp(cJSON_GetStringValue(in), "path") != 0)
                continue;

            name = cJSON_GetObjectItemCaseSensitive(parameter, "name");
            assert(cJSON_IsString(name));

            description = cJSON_GetObjectItemCaseSensitive(parameter, "description");
            assert(cJSON_IsString(description));

            fprintf(output, "\t%s\n", cJSON_GetStringValue(name));
            fprintf(output, "\t\t%s\n", cJSON_GetStringValue(description));
        }
    }

    if (request_body != REQUEST_BODY_EMPTY) {
        fprintf(output, "\tbody\n");
        fprintf(output, "\t\tData to pass the body of the request.\n");
    }

    x_formats = cJSON_GetObjectItemCaseSensitive(method, "x-formats");
    if (!x_formats)
        return;
    assert(cJSON_IsObject(x_formats) && cJSON_GetArraySize(x_formats) > 0);

    fprintf(output, "\nFormats:\n");
    for (cJSON *f = x_formats->child; f; f = f->next) {
        cJSON *format, *type, *config;
        enum tablular_type tabular_type;
        enum format format_type;

        format = follow_ref(f);
        assert(cJSON_IsObject(format));

        fprintf(output, "\t%s\n", format->string);

        format_type = format_from_string(format->string);
        assert(format_type != FORMAT_INVALID);
        if (format_type != FORMAT_TABULAR)
            continue;

        type = cJSON_GetObjectItemCaseSensitive(format, "type");
        assert(cJSON_IsString(type));

        tabular_type = tabular_type_from_string(cJSON_GetStringValue(type));

        config = cJSON_GetObjectItemCaseSensitive(format, "config");

        assert(!columnv);

        fprintf(output, "\t\t\"tab\" will print all columns.\n");
        fprintf(output, "\t\t\"tab:COL1,COL2\" will print only COL1 and COL2.\n");

        switch (tabular_type) {
        case TABULAR_ARRAY: {
            cJSON *columns;

            assert(cJSON_IsObject(config));

            columns = cJSON_GetObjectItemCaseSensitive(config, "columns");
            assert(cJSON_IsObject(columns));

            columnc = cJSON_GetArraySize(columns);
            columnv = malloc(columnc * sizeof(*columnv));
            if (!columnv)
                return;

            for (size_t i = 0; i < columnc; i++) {
                cJSON *c = cJSON_GetArrayItem(columns, i);

                columnv[i] = c->string;
            }

            break;
        }
        case TABULAR_FLATTENED: {
            cJSON *columns;

            assert(cJSON_IsObject(config));

            columns = cJSON_GetObjectItemCaseSensitive(config, "columns");
            assert(cJSON_IsArray(columns));

            columnc = cJSON_GetArraySize(columns);
            columnv = malloc(columnc * sizeof(*columnv));
            if (!columnv)
                return;

            for (size_t i = 0; i < columnc; i++) {
                cJSON *c = cJSON_GetArrayItem(columns, i);

                columnv[i] = cJSON_GetStringValue(c);
            }

            break;
        }
        case TABULAR_CUSTOM: {
            void *handle;
            size_t *columncp;
            char symbol[128];
            const char **headers;
            int rc HSE_MAYBE_UNUSED;

            handle = dlopen(NULL, RTLD_LAZY);
            assert(handle);

            rc = snprintf(symbol, sizeof(symbol), "%s_columnc", operation_id);
            assert(rc < sizeof(symbol) && rc > 0);
            strchrrep(symbol, '-', '_');

            columncp = dlsym(handle, symbol);
            assert(columncp);
            columnc = *columncp;

            rc = snprintf(symbol, sizeof(symbol), "%s_headers", operation_id);
            assert(rc < sizeof(symbol) && rc > 0);
            strchrrep(symbol, '-', '_');

            headers = dlsym(handle, symbol);
            assert(headers);

            rc = dlclose(handle);
            assert(rc == 0);

            columnv = malloc(columnc * sizeof(*columnv));
            if (!columnv)
                return;

            for (size_t i = 0; i < columnc; i++)
                columnv[i] = headers[i];

            break;
        }
        }
    }

    if (!columnv)
        return;

    fprintf(output, "\nColumns:\n");
    for (size_t i = 0; i < columnc; i++)
        fprintf(output, "\t%s\n", columnv[i]);

    free(columnv);
}

static int
evaluate_options(
    const char *const operation_id,
    cJSON *const path,
    cJSON *const method,
    const int argc,
    char **const argv,
    bool *const head_to_exit)
{
    void *buf;
    int rc = 0;
    cJSON *x_options;
    char *shortopts, *ptr;
    int c, len, cache, longind;
    struct option *longopts = NULL;

    INVARIANT(operation_id);
    INVARIANT(cJSON_IsObject(path));
    INVARIANT(cJSON_IsObject(method));
    INVARIANT(head_to_exit);

    *head_to_exit = false;

    /* Save so that it can be reset */
    cache = optind;

    x_options = cJSON_GetObjectItemCaseSensitive(method, "x-options");
    assert(cJSON_IsArray(x_options));

    len = cJSON_GetArraySize(x_options);

    /* The +1 represents the zeroed struct in the array. The coefficient 2
     * represents one character for the option and one for the optional ':'
     * character. The additive 3 is corresponds to "+:\0".
     */
    buf = calloc(1, (len + 1) * sizeof(*longopts) + (2 * len + 3) * sizeof(*shortopts));
    if (!buf)
        return EX_USAGE;

    longopts = buf;
    shortopts = (char *)(longopts + len + 1);
    ptr = shortopts;
    *(ptr++) = '+';
    *(ptr++) = ':';

    for (int i = 0; i < len; i++) {
        struct option *longopt;
        cJSON *o, *option, *shortstr, *longstr, *requires_argument;

        longopt = longopts + i;

        o = cJSON_GetArrayItem(x_options, i);
        assert(cJSON_IsObject(o));

        option = follow_ref(o);
        assert(cJSON_IsObject(option));

        shortstr = cJSON_GetObjectItemCaseSensitive(option, "short");
        longstr = cJSON_GetObjectItemCaseSensitive(option, "long");
        assert(cJSON_IsString(shortstr));
        assert(cJSON_IsString(longstr));

        (*ptr++) = *cJSON_GetStringValue(shortstr);
        longopt->name = cJSON_GetStringValue(longstr);
        longopt->val = *cJSON_GetStringValue(shortstr);
        longopt->flag = NULL;

        requires_argument = cJSON_GetObjectItemCaseSensitive(option, "requires-argument");
        if (cJSON_IsTrue(requires_argument)) {
            *(ptr++) = ':';
            longopt->has_arg = required_argument;
        } else {
            longopt->has_arg = no_argument;
        }
    }

    optind = 0;
    while ((c = getopt_long(argc, argv, shortopts, longopts, &longind)) != -1) {
        switch (c) {
        case 'h':
            *head_to_exit = true;
            operation_usage(stdout, operation_id, path, method);
            goto out;
        case 'f':
            output_format.type = format_from_string(optarg);
            if (output_format.type == FORMAT_INVALID) {
                fprintf(stderr, "Invalid format string: %s\n", optarg);
                operation_usage(stderr, operation_id, path, method);
                rc = EX_USAGE;
                goto out;
            }

            rc = evaluate_format_option(operation_id, path, method, optarg);
            if (rc)
                goto out;

            break;
        case ':':
            fprintf(stderr, "Invalid argument for option '-%c'\n", c);
            operation_usage(stderr, operation_id, path, method);
            rc = EX_USAGE;
            goto out;
        default: {
            bool found = false;
            for (cJSON *o = x_options->child; o; o = o->next) {
                cJSON *option;

                option = follow_ref(o);
                assert(cJSON_IsObject(option));

                if (*cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(option, "short")) == c) {
                    merr_t err;
                    const char *type;
                    cJSON *parameter, *schema_type;

                    parameter = cJSON_GetObjectItemCaseSensitive(option, "parameter");
                    if (!parameter)
                        continue;
                    assert(cJSON_IsString(parameter));
                    parameter = cJSONUtils_GetPointerCaseSensitive(openapi,
                        cJSON_GetStringValue(parameter) + 1); /* Move past octothorpe */
                    assert(cJSON_IsObject(parameter));

                    schema_type = cJSONUtils_GetPointerCaseSensitive(parameter,
                        "/schema/type");
                    assert(cJSON_IsString(schema_type));
                    type = cJSON_GetStringValue(schema_type);
                    if (strcmp(type, "boolean") == 0) {
                        if (optarg) {
                            fprintf(stderr, "Option does not require a value: -%c\n", c);
                            rc = EX_USAGE;
                            goto out;
                        }

                        err = options_map_put(options_map, parameter->string, "true");
                    } else {
                        abort();
                    }

                    if (err) {
                        rc = EX_OSERR;
                        goto out;
                    }

                    found = true;
                    break;
                }
            }

            if (!found) {
                operation_usage(stderr, operation_id, path, method);
                fprintf(stderr, "Unknown option: -%c\n", c == '?' ? optopt : c);
                rc = EX_USAGE;
                goto out;
            }

            break;
        }
        }
    }

out:
    /* Restore optind and move it forward */
    optind += cache;

    free(buf);

    return rc;
}

static int
realize_path(
    const char *const template,
    struct buffer *const endpoint,
    const int argc,
    char **const argv)
{
    INVARIANT(template);
    INVARIANT(endpoint);

    for (size_t i = 0, j = 0; i < strlen(template); i++) {
        merr_t err;

        if (template[i] == '{') {
            const char *pattern = template + i;
            const char *end = strchr(pattern, '}');
            const char *arg = argv[j++];
            optind++;

            while (pattern++ != end)
                i++;

            /* This is a templated endpoint, so replace all the stuff in {...}
             * with arguments from the command line.
             */
            err = buffer_append(endpoint, arg, strlen(arg));
            if (err) {
                fprintf(stderr, "Failed to allocate memory\n");
                return EX_OSERR;
            }
        } else {
            err = buffer_putc(endpoint, template[i]);
            if (err) {
                fprintf(stderr, "Failed to allocate memory\n");
                return EX_OSERR;
            }
        }
    }

    return 0;
}

static int
append_query_parameters(cJSON *const method, struct buffer *const endpoint)
{
    merr_t err;
    cJSON *parameters;

    INVARIANT(cJSON_IsObject(method));
    INVARIANT(endpoint);

    parameters = cJSON_GetObjectItemCaseSensitive(method, "parameters");
    if (!parameters)
        return 0;

    assert(cJSON_IsArray(parameters));

    if (cJSON_GetArraySize(parameters) == 0)
        return 0;

    /* Begin query parameters */
    err = buffer_putc(endpoint, '?');
    if (err) {
        fprintf(stderr, "Failed to allocate memory\n");
        return EX_OSERR;
    }

    for (cJSON *p = parameters->child; p; p = p->next) {
        const char *value;
        cJSON *param, *in HSE_MAYBE_UNUSED, *name;

        assert(cJSON_IsObject(p));
        param = follow_ref(p);
        assert(cJSON_IsObject(param));

        in = cJSON_GetObjectItemCaseSensitive(param, "in");
        assert(cJSON_IsString(in));
        assert(strcmp(cJSON_GetStringValue(in), "query") == 0);
        name = cJSON_GetObjectItemCaseSensitive(param, "name");
        assert(cJSON_IsString(name));

        value = options_map_get(options_map, cJSON_GetStringValue(name));
        if (!value)
            continue;

        if (endpoint->data[endpoint->len - 1] != '?') {
            err = buffer_putc(endpoint, '&');
            if (err) {
                fprintf(stderr, "Failed to allocate memory\n");
                return EX_OSERR;
            }
        }

        err = buffer_sprintf(endpoint, "%s=%s", param->string, value);
        if (err) {
            fprintf(stderr, "Failed to allocate memory\n");
            return EX_OSERR;
        }
    }

    /* Clean up endpoint if junk at the end */
    if (endpoint->data[endpoint->len - 1] == '?' || endpoint->data[endpoint->len - 1] == '&')
        buffer_erase(endpoint, 1);

    return 0;
}

static int
parse_body(
    cJSON *const method,
    const int argc,
    char **const argv,
    struct curl_slist **const headers,
    char **data,
    size_t *data_len)
{
    int rc = 0;
    cJSON *body;

    INVARIANT(method);
    INVARIANT(argv);
    INVARIANT(headers);
    INVARIANT(data);
    INVARIANT(data_len);

    *data = NULL;
    *data_len = 0;

    if (argc - optind == 0)
        return 0;

    body = cJSON_Parse(argv[optind]);
    if (!body) {
        char *tmp;
        size_t len;

        len = strlen(argv[optind]);
        tmp = malloc(len + 3);
        if (!tmp) {
            fprintf(stderr, "Failed to allocate memory\n");
            rc = EX_OSERR;
            goto out;
        }

        snprintf(tmp, len + 3, "\"%s\"", argv[optind]);
        body = cJSON_Parse(tmp);
        free(tmp);
        if (!body) {
            fprintf(stderr, "Body argument is not valid JSON\n");
            rc = EX_DATAERR;
            goto out;
        }
    }

    if (body) {
        *data = cJSON_PrintUnformatted(body);
        if (!*data) {
            fprintf(stderr, "Failed to allocate memory\n");
            rc = EX_OSERR;
            goto out;
        }

        *data_len = strlen(*data);
        *headers = curl_slist_append(*headers, "Content-Type: application/json");
        if (!headers) {
            fprintf(stderr, "Failed to allocate memory\n");
            rc = EX_OSERR;
            goto out;
        }
    }

out:
    optind++;
    cJSON_Delete(body);

    return rc;
}

static void
root_usage(FILE *const output)
{
    INVARIANT(openapi);
    INVARIANT(output);

    fprintf(output, "Usage: hsettp [OPTION]... <operation> [OPTION]... [ARGS]...\n\n");
    fprintf(output, "Options:\n");
    fprintf(output, "\t-h, --help\n");
    fprintf(output, "\t\tPrint the help output.\n");
    fprintf(output, "\t-s, --socket\n");
    fprintf(output, "\t\tPath to the HSE socket file.\n\n");
    fprintf(output, "Operations:\n");
    print_operations(output);
}

int
main(const int argc, char **const argv)
{
    int c;
    int rc = 0;
    merr_t err;
    size_t len;
    char *data = NULL;
    size_t data_len = 0;
    const char *operation_id;
    bool head_to_exit = false;
    struct buffer endpoint = { 0 };
    enum request_body request_body;
    unsigned int operation_arguments;
    struct curl_slist *headers = NULL;
    cJSON *path = NULL, *method = NULL;
    const char *socket = "/tmp/hse.sock";

    openapi = cJSON_ParseWithLength((char *)openapi_json, sizeof(openapi_json));
    if (!openapi) {
        fprintf(stderr, "Failed to allocate memory\n");
        rc = EX_OSERR;
        goto out;
    }
    assert(cJSON_IsObject(openapi));

    while ((c = getopt_long(argc, argv, "+:hs:", program_opts, NULL)) != -1) {
        switch (c) {
        case 'h':
            root_usage(stdout);
            goto out;
        case 's':
            socket = optarg;
            break;
        case ':':
            fprintf(stderr, "Invalid argument for option '-%c'\n", c);
            root_usage(stderr);
            rc = EX_USAGE;
            goto out;
        case '?':
            fprintf(stderr, "Unknown option '-%c'\n", optopt);
            root_usage(stderr);
            rc = EX_USAGE;
            goto out;
        default:
            fprintf(stderr, "Unknown option '-%c'\n", c);
            root_usage(stderr);
            rc = EX_USAGE;
            goto out;
        }
    }

    options_map = options_map_create(8);
    if (!options_map) {
        fprintf(stderr, "Failed to allocate memory\n");
        rc = EX_OSERR;
        goto out;
    }

    if (optind >= argc) {
        fprintf(stderr, "Missing operation\n");
        root_usage(stderr);
        rc = EX_USAGE;
        goto out;
    }

    operation_id = argv[optind];
    if (!find_operation(operation_id, &path, &method)) {
        fprintf(stderr, "Unknown operation: %s\n", operation_id);
        root_usage(stderr);
        rc = EX_USAGE;
        goto out;
    }

    assert(path);
    assert(method);

    /* Evaluate method options */
    rc = evaluate_options(operation_id, path, method, argc - optind, argv + optind, &head_to_exit);
    if (rc || head_to_exit)
        goto out;

    /* Validate number of remaining arguments */
    operation_arguments = count_operation_arguments(path, method, &request_body);
    switch (request_body) {
    case REQUEST_BODY_REQUIRED:
        operation_arguments++;
        /* fallthrough */
    case REQUEST_BODY_OPTIONAL:
    case REQUEST_BODY_EMPTY:
        break;
    }
    if (argc - optind != operation_arguments &&
            !(request_body == REQUEST_BODY_OPTIONAL && argc - optind != operation_arguments + 1)) {
        fprintf(stderr, "Wrong number of arguments provided\n");
        operation_usage(stderr, operation_id, path, method);
        rc = EX_USAGE;
        goto out;
    }

    /* Setup the buffer */
    len = strlen(path->string);
    err = buffer_init(&endpoint, len);
    if (err) {
        char buf[256];

        merr_strinfo(err, buf, sizeof(buf), NULL, NULL);
        fprintf(stderr, "Failed to initialize a buffer: %s\n", buf);
        rc = EX_OSERR;
        goto out;
    }

    /* Substitute arguments for {...} templating in string */
    rc = realize_path(path->string, &endpoint, argc - optind, argv + optind);
    if (rc)
        goto out;

    /* Retrieve the request body from the command line */
    rc = parse_body(method, argc, argv, &headers, &data, &data_len);
    if (rc)
        goto out;

    /* At this point, we should have exhausted all arguments on the command
     * line.
     */
    assert(optind == argc);

    rc = append_query_parameters(method, &endpoint);
    if (rc)
        goto out;

    err = rest_client_init(socket);
    if (err) {
        char buf[256];

        merr_strinfo(err, buf, sizeof(buf), (merr_stringify *)curl_easy_strerror, NULL);
        fprintf(stderr, "Failed to initialize the REST client: %s\n", buf);
        rc = EX_OSERR;
        goto out;
    }

    /* Since endpoint is generated using user data, use the safe variant of the
     * fetch function.
     */
    err = rest_client_fetch_s(capitalized_method(method->string), headers, data, data_len, rest_cb,
        NULL, endpoint.data);
    if (err) {
        char buf[256];

        merr_strinfo(err, buf, sizeof(buf), (merr_stringify *)curl_easy_strerror, NULL);
        fprintf(stderr, "Request failed: %s\n", buf);
        rc = EX_DATAERR;
        goto out;
    }

out:
    rest_client_fini();

    if (output_format.type == FORMAT_TABULAR) {
        switch (output_format.config.tab.type) {
        case TABULAR_ARRAY:
            free(output_format.config.tab.ext.array.pointers);
            /* fallthrough */
        case TABULAR_FLATTENED:
            free(output_format.config.tab.headers);
            free(output_format.config.tab.justify);
            free(output_format.config.tab.enabled);
            break;
        case TABULAR_CUSTOM:
            break;
        }
    }

    cJSON_free(data);
    curl_slist_free_all(headers);
    buffer_destroy(&endpoint);
    cJSON_Delete(openapi);
    options_map_destroy(options_map);

    return rc;
}
