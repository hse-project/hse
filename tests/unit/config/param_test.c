/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#include <hse/config/params.h>
#include <hse/util/base.h>
#include <hse/util/storage.h>

#include <hse/test/mtf/framework.h>

struct test_arr_type {
    int8_t field1;
};

struct test_params {
    bool test1;
    uint8_t test_uint8;
    uint16_t test_uint16;
    uint32_t test_uint32;
    uint64_t test_uint64;
    size_t test_size;
    int test_int;
    int8_t test_int8;
    int16_t test_int16;
    int32_t test_int32;
    int64_t test_int64;
    char test_string[12];
    struct test_arr_type test_array[2];

    uint64_t test_uint64a;
    uint64_t test_uint64b;
    uint64_t test_uint64c;
    uint64_t test_uint64d;

    uint32_t test_uint32a;

    double test_double;

} params;

bool
relation_validate(const struct param_spec * const ps, const void * const params)
{
    const struct test_params *p = params;

    return p->test_uint32a > p->test_uint8;
}

bool
array_converter(const struct param_spec * const ps, const cJSON * const node, void * const data)
{
    int i = 0;
    struct test_arr_type *arr = data;

    if (!cJSON_IsArray(node))
        return false;

    for (const cJSON *n = node->child; n; n = n->next, i++) {
        cJSON *field1 = cJSON_GetObjectItemCaseSensitive(n, "field1");
        if (!cJSON_IsNumber(field1))
            return false;

        arr[i].field1 = (int8_t)cJSON_GetNumberValue(field1);
    }

    return true;
}

bool
array_validator(const struct param_spec * const ps, const void * const data)
{
    const struct test_arr_type *arr = data;

    return arr[0].field1 < 10 && arr[1].field1 < 10;
}

void
array_default_builder(const struct param_spec * const ps, void * const data)
{
    struct test_arr_type *arr = data;

    arr[0].field1 = 5;
    arr[1].field1 = 6;
}

bool
array_relation_validate(const struct param_spec * const ps, const void * const params)
{
    const struct test_params *p = params;

    return p->test_array[0].field1 < p->test_int32 && p->test_array[1].field1 < p->test_int16;
}

merr_t
array_stringify(
    const struct param_spec * const ps,
    const void * const value,
    char * const buf,
    const size_t buf_sz,
    size_t * const needed_sz)
{
    const struct test_arr_type *arr = (struct test_arr_type *)value;
    int n;

    n = snprintf(buf, buf_sz, "[{\"field1\": %d}, {\"field1\": %d}]", arr[0].field1, arr[1].field1);
    assert(n >= 0);

    if (needed_sz)
        *needed_sz = n;

    return 0;
}

cJSON *
array_jsonify(const struct param_spec * const ps, const void * const value)
{
    cJSON *node;
    const struct test_arr_type *arr;

    node = cJSON_CreateArray();
    if (!node)
        return NULL;

    arr = (struct test_arr_type *)value;

    for (int i = 0; i < 2; i++) {
        cJSON *n = cJSON_CreateObject();
        if (!n)
            goto out;

        cJSON_AddNumberToObject(n, "field1", arr->field1);

        cJSON_AddItemToArray(node, n);
    }

    return node;

out:
    cJSON_Delete(node);

    return NULL;
}

const struct param_spec pspecs[] = {
    {
        .ps_name = "test1",
        .ps_description = "test1",
        .ps_flags = PARAM_WRITABLE,
        .ps_type = PARAM_TYPE_BOOL,
        .ps_offset = offsetof(struct test_params, test1),
        .ps_size = PARAM_SZ(struct test_params, test1),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_bool = true,
        },
    },
    {
        .ps_name = "test_uint8",
        .ps_description = "test_uint8",
        .ps_flags = PARAM_WRITABLE,
        .ps_type = PARAM_TYPE_U8,
        .ps_offset = offsetof(struct test_params, test_uint8),
        .ps_size = PARAM_SZ(struct test_params, test_uint8),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 2,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT8_MAX,
            },
        },
    },
    {
        .ps_name = "test_uint16",
        .ps_description = "test_uint16",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_U16,
        .ps_offset = offsetof(struct test_params, test_uint16),
        .ps_size = PARAM_SZ(struct test_params, test_uint16),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 3,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT16_MAX,
            },
        },
    },
    {
        .ps_name = "test_uint32",
        .ps_description = "test_uint32",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct test_params, test_uint32),
        .ps_size = PARAM_SZ(struct test_params, test_uint32),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 4,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            },
        },
    },
    {
        .ps_name = "test_uint64",
        .ps_description = "test_uint64",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct test_params, test_uint64),
        .ps_size = PARAM_SZ(struct test_params, test_uint64),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 5,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "test_size",
        .ps_description = "test_size",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_SIZE,
        .ps_offset = offsetof(struct test_params, test_size),
        .ps_size = PARAM_SZ(struct test_params, test_size),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 6,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = SIZE_MAX,
            },
        },
    },
    {
        .ps_name = "test_int",
        .ps_description = "test_int",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_INT,
        .ps_offset = offsetof(struct test_params, test_int),
        .ps_size = PARAM_SZ(struct test_params, test_int),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_scalar = 6,
        },
        .ps_bounds = {
            .as_scalar = {
                .ps_min = INT_MIN,
                .ps_max = INT_MAX,
            },
        },
    },
    {
        .ps_name = "test_int8",
        .ps_description = "test_int8",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_I8,
        .ps_offset = offsetof(struct test_params, test_int8),
        .ps_size = PARAM_SZ(struct test_params, test_int8),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_scalar = 7,
        },
        .ps_bounds = {
            .as_scalar = {
                .ps_min = INT8_MIN,
                .ps_max = INT8_MAX,
            },
        },
    },
    {
        .ps_name = "test_int16",
        .ps_description = "test_int16",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_I16,
        .ps_offset = offsetof(struct test_params, test_int16),
        .ps_size = PARAM_SZ(struct test_params, test_int16),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_scalar = 8,
        },
        .ps_bounds = {
            .as_scalar = {
                .ps_min = INT16_MIN,
                .ps_max = INT16_MAX,
            },
        },
    },
    {
        .ps_name = "test_int32",
        .ps_description = "test_int32",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_I32,
        .ps_offset = offsetof(struct test_params, test_int32),
        .ps_size = PARAM_SZ(struct test_params, test_int32),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_scalar = 9,
        },
        .ps_bounds = {
            .as_scalar = {
                .ps_min = INT32_MIN,
                .ps_max = INT32_MAX,
            },
        },
    },
    {
        .ps_name = "test_int64",
        .ps_description = "test_int64",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_I64,
        .ps_offset = offsetof(struct test_params, test_int64),
        .ps_size = PARAM_SZ(struct test_params, test_int64),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_scalar = 10,
        },
        .ps_bounds = {
            .as_scalar = {
                .ps_min = INT64_MIN,
                .ps_max = INT64_MAX,
            },
        },
    },
    {
        .ps_name = "test_string",
        .ps_description = "test_string",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_STRING,
        .ps_offset = offsetof(struct test_params, test_string),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_string = "default",
        },
        .ps_bounds = {
            .as_string = {
                .ps_max_len = PARAM_SZ(struct test_params, test_string),
            },
        },
    },
    {
        .ps_name = "test_array",
        .ps_description = "test_array",
        .ps_flags = PARAM_DEFAULT_BUILDER,
        .ps_type = PARAM_TYPE_ARRAY,
        .ps_offset = offsetof(struct test_params, test_array),
        .ps_convert = array_converter,
        .ps_validate = array_validator,
        .ps_stringify = array_stringify,
        .ps_jsonify = array_jsonify,
        .ps_validate_relations = array_relation_validate,
        .ps_default_value = {
            .as_builder = array_default_builder,
        },
    },
    {
        .ps_name = "test_uint64a",
        .ps_description = "test_uint64a",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct test_params, test_uint64a),
        .ps_size = PARAM_SZ(struct test_params, test_uint64a),
        .ps_convert = param_convert_to_bytes_from_KB,
        .ps_validate = param_default_validator,
        .ps_stringify = param_stringify_bytes_to_KB,
        .ps_jsonify = param_jsonify_bytes_to_KB,
        .ps_default_value = {
            .as_uscalar = 4 * KB,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "test_uint64b",
        .ps_description = "test_uint64b",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct test_params, test_uint64b),
        .ps_size = PARAM_SZ(struct test_params, test_uint64b),
        .ps_convert = param_convert_to_bytes_from_MB,
        .ps_validate = param_default_validator,
        .ps_stringify = param_stringify_bytes_to_MB,
        .ps_jsonify = param_jsonify_bytes_to_MB,
        .ps_default_value = {
            .as_uscalar = 4 * MB,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "test_uint64c",
        .ps_description = "test_uint64c",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct test_params, test_uint64c),
        .ps_size = PARAM_SZ(struct test_params, test_uint64c),
        .ps_convert = param_convert_to_bytes_from_GB,
        .ps_validate = param_default_validator,
        .ps_stringify = param_stringify_bytes_to_GB,
        .ps_jsonify = param_jsonify_bytes_to_GB,
        .ps_default_value = {
            .as_uscalar = 4 * GB,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "test_uint64d",
        .ps_description = "test_uint64d",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct test_params, test_uint64d),
        .ps_size = PARAM_SZ(struct test_params, test_uint64d),
        .ps_convert = param_convert_to_bytes_from_TB,
        .ps_validate = param_default_validator,
        .ps_stringify = param_stringify_bytes_to_TB,
        .ps_jsonify = param_jsonify_bytes_to_TB,
        .ps_default_value = {
            .as_uscalar = 4 * TB,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "test_uint32a",
        .ps_description = "test_uint32a",
        .ps_flags = PARAM_WRITABLE,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct test_params, test_uint32a),
        .ps_size = PARAM_SZ(struct test_params, test_uint32a),
        .ps_convert = param_roundup_pow2,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_validate_relations = relation_validate,
        .ps_default_value = {
            .as_uscalar = 1000,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT16_MAX,
            },
        },
    },
    {
        .ps_name = "test_double",
        .ps_description = "test_double",
        .ps_flags = PARAM_WRITABLE,
        .ps_type = PARAM_TYPE_DOUBLE,
        .ps_offset = offsetof(struct test_params, test_double),
        .ps_size = PARAM_SZ(struct test_params, test_double),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_double = 0.5,
        },
        .ps_bounds = {
            .as_double = {
                .ps_min = -1.222e6,
                .ps_max = +1.222e6,
            },
        },
    },
};

int
test_pre(struct mtf_test_info *ti)
{
    params_from_defaults(&params, NELEM(pspecs), pspecs);

    return 0;
}

const struct param_spec *
ps_get(const char * const name)
{
    assert(name);

    for (size_t i = 0; i < NELEM(pspecs); i++) {
        if (!strcmp(pspecs[i].ps_name, name))
            return &pspecs[i];
    }

    return NULL;
}

/**
 * Check the validity of various key=value combinations
 */
merr_t HSE_SENTINEL
check(const char * const arg, ...)
{
    merr_t err;
    bool success;
    const char *a = arg;
    va_list ap;

    assert(arg);

    va_start(ap, arg);

    do {
        const char *paramv[] = { a };
        const size_t paramc = NELEM(paramv);

        success = !!va_arg(ap, int);

        err = params_from_paramv(&params, paramc, paramv, NELEM(pspecs), pspecs);
        if (success != !err) {
            if (!err)
                err = merr(EINVAL);
            log_info("test case failed: %s\n", a);
            break;
        } else {
            /* Reset err because we expected it */
            err = 0;
        }
    } while ((a = va_arg(ap, char *)));

    va_end(ap);

    return err;
}

MTF_BEGIN_UTEST_COLLECTION(param_test)

MTF_DEFINE_UTEST_PRE(param_test, defaults, test_pre)
{
    ASSERT_EQ(true, params.test1);
    ASSERT_EQ(2, params.test_uint8);
    ASSERT_EQ(3, params.test_uint16);
    ASSERT_EQ(4, params.test_uint32);
    ASSERT_EQ(5, params.test_uint64);
    ASSERT_EQ(6, params.test_size);
    ASSERT_EQ(6, params.test_int);
    ASSERT_EQ(7, params.test_int8);
    ASSERT_EQ(8, params.test_int16);
    ASSERT_EQ(9, params.test_int32);
    ASSERT_EQ(10, params.test_int64);
    ASSERT_STREQ("default", params.test_string);
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_bool, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test1");

    err = ps->ps_stringify(ps, &params.test1, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(4, needed_sz);
    ASSERT_STREQ("true", buf);

    /* clang-format off */
    err = check(
        "test1=true", true,
        "test1=false", true,
        "test1=1", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_u8, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_uint8");

    err = ps->ps_stringify(ps, &params.test_uint8, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(1, needed_sz);
    ASSERT_STREQ("2", buf);

    /* clang-format off */
    err = check(
        "test_uint8=0", true,
        "test_uint8=12", true,
        "test_uint8=255", true,
        "test_uint8=256", false,
        "test_uint8=-1", false,
        "test_uint8=1.5", false,
        "test_uint8=wrong", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_u16, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_uint16");

    err = ps->ps_stringify(ps, &params.test_uint16, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(1, needed_sz);
    ASSERT_STREQ("3", buf);

    /* clang-format off */
    err = check(
        "test_uint16=0", true,
        "test_uint16=12", true,
        "test_uint16=65535", true,
        "test_uint16=65536", false,
        "test_uint16=-1", false,
        "test_uint16=1.5", false,
        "test_uint16=wrong", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_u32, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_uint32");

    err = ps->ps_stringify(ps, &params.test_uint32, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(1, needed_sz);
    ASSERT_STREQ("4", buf);

    /* clang-format off */
    err = check(
        "test_uint32=0", true,
        "test_uint32=12", true,
        "test_uint32=4294967295", true,
        "test_uint32=4294967296", false,
        "test_uint32=-1", false,
        "test_uint32=1.5", false,
        "test_uint32=wrong", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_u64, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_uint64");

    err = ps->ps_stringify(ps, &params.test_uint64, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(1, needed_sz);
    ASSERT_STREQ("5", buf);

    /* clang-format off */
    err = check(
        "test_uint64=0", true,
        "test_uint64=12", true,
        "test_uint64=18446744073709551615", false,
        /* out of range or invalid syntax */
        "test_uint64=18446744073709551616", false,
        "test_uint64=-1", false,
        "test_uint64=1.5", false,
        "test_uint64=wrong", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_size, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_size");

    err = ps->ps_stringify(ps, &params.test_uint64, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(1, needed_sz);
    ASSERT_STREQ("5", buf);

    /* clang-format off */
    err = check(
        "test_size=0", true,
        "test_size=12", true,
#if SIZE_MAX == UINT64_MAX
        "test_size=18446744073709551615", false,
        /* out of range or invalid syntax */
        "test_size=18446744073709551616", false,
#elif SIZE_MAX == UINT32_MAX
        "test_size=4294967295", true,
        "test_size=4294967296", false,
#elif SIZE_MAX == UINT16_MAX
        "test_size=65535", true,
        "test_size=65536", false,
#else
#warning "Unhandled size_t width"
#endif
        "test_size=-1", false,
        "test_size=1.5", false,
        "test_size=wrong", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_int, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_int");

    err = ps->ps_stringify(ps, &params.test_int, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(1, needed_sz);
    ASSERT_STREQ("6", buf);

    /* clang-format off */
    err = check(
        "test_int=-2147483649", false,
        "test_int=-2147483648", true,
        "test_int=-1", true,
        "test_int=0", true,
        "test_int=1", true,
        "test_int=2147483647", true,
        "test_int=2147483648", false,
        "test_int=1.5", false,
        "test_int=wrong", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_i8, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_int8");

    err = ps->ps_stringify(ps, &params.test_int8, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(1, needed_sz);
    ASSERT_STREQ("7", buf);

    /* clang-format off */
    err = check(
        "test_int8=-129", false,
        "test_int8=-128", true,
        "test_int8=12", true,
        "test_int8=127", true,
        "test_int8=128", false,
        "test_int8=1.5", false,
        "test_int8=wrong", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_i16, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_int16");

    err = ps->ps_stringify(ps, &params.test_int16, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(1, needed_sz);
    ASSERT_STREQ("8", buf);

    /* clang-format off */
    err = check(
        //"test_int16=-32769", false,  (deserialize BUG?)
        //"test_int16=-32768", true,   (deserialize BUG?)
        "test_int16=12", true,
        "test_int16=32767", true,
        "test_int16=32768", false,
        "test_int16=1.5", false,
        "test_int16=wrong", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_i32, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_int32");

    err = ps->ps_stringify(ps, &params.test_int32, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(1, needed_sz);
    ASSERT_STREQ("9", buf);

    /* clang-format off */
    err = check(
        //"test_int32=-2147483649", false, (deserialize BUG?)
        //"test_int32=-2147483648", true,  (deserialize BUG?)
        "test_int32=999", true,
        "test_int32=2147483647", true,
        "test_int32=2147483648", false,
        "test_int32=1.5", false,
        "test_int32=wrong", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_i64, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_int64");

    err = ps->ps_stringify(ps, &params.test_int64, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(2, needed_sz);
    ASSERT_STREQ("10", buf);

    /* clang-format off */
    err = check(
        "test_int64=-9223372036854775809", true,
        "test_int64=-9223372036854775808", true,
        "test_int64=12", true,
        "test_int64=9223372036854775807", false,
        "test_int64=9223372036854775808", false,
        "test_int64=1.5", false,
        "test_int64=wrong", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_double, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_double");

    err = ps->ps_stringify(ps, &params.test_int32, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(8, needed_sz);
    ASSERT_STREQ("0.000000", buf);

    err = check(
        "test_double=12", true, "test_double=1.5", true, "test_double=-0.01", true,
        "test_double=100.", true,

        /* Range checks based on min/max set in param spec.
         */
        "test_double=-1.223e6", false, /* too small */
        "test_double=-1.222e6", true,  /* min value */
        "test_double=-1.221e6", true,  /* in range */
        "test_double=1.221e6", true,   /* in range */
        "test_double=1.222e6", true,   /* max value */
        "test_double=1.223e6", false,  /* too large */

        /* Invalid syntax.
         */
        "test_double=.1", false, "test_double=9223372036854775808", false, "test_double=wrong",
        false,

        /* These should fail due to invalid syntax, but cJSON parse allows
         * it. Leaving them here as "expect success" so they can be converted to
         * "expect failures" if/when we replace cJSON.
         */
        "test_double=1.1FOOBAR", true, "test_double=1.1z", true,

        NULL);

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_string, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_string");

    err = ps->ps_stringify(ps, &params.test_string, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(9, needed_sz);
    ASSERT_STREQ("\"default\"", buf);

    /* clang-format off */
    err = check(
        "test_string=yes", true,
        "test_string=\"yes\"", true,
        "test_string=this-is-a-long-string-please-fail", false,
        "test_string=false", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_array, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_array");

    err = ps->ps_stringify(ps, &params.test_array, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(30, needed_sz);
    ASSERT_STREQ("[{\"field1\": 5}, {\"field1\": 6}]", buf);

    /* clang-format off */
    err = check(
        "test_array=[{\"field1\": 0}, {\"field1\": 1}]", true,
        "test_array=[{\"field1\": 0}, {\"field1\": 11}]", false,
        "test_array=false", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, to_bytes_from_KB, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_uint64a");

    err = ps->ps_stringify(ps, &params.test_uint64a, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(1, needed_sz);
    ASSERT_STREQ("4", buf);

    /* clang-format off */
    err = check(
        "test_uint64a=5", true,
        "test_uint64a=hello", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(5 * KB, params.test_uint64a);
}

MTF_DEFINE_UTEST_PRE(param_test, to_bytes_from_MB, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_uint64b");

    err = ps->ps_stringify(ps, &params.test_uint64b, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(1, needed_sz);
    ASSERT_STREQ("4", buf);

    /* clang-format off */
    err = check(
        "test_uint64b=5", true,
        "test_uint64b=hello", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(5 * MB, params.test_uint64b);
}

MTF_DEFINE_UTEST_PRE(param_test, to_bytes_from_GB, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_uint64c");

    err = ps->ps_stringify(ps, &params.test_uint64c, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(1, needed_sz);
    ASSERT_STREQ("4", buf);

    /* clang-format off */
    err = check(
        "test_uint64c=5", true,
        "test_uint64c=hello", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(5 * GB, params.test_uint64c);
}

MTF_DEFINE_UTEST_PRE(param_test, to_bytes_from_TB, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    const struct param_spec *ps = ps_get("test_uint64d");

    err = ps->ps_stringify(ps, &params.test_uint64d, buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(1, needed_sz);
    ASSERT_STREQ("4", buf);

    /* clang-format off */
    err = check(
        "test_uint64d=5", true,
        "test_uint64d=hello", false,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(5 * TB, params.test_uint64d);
}

MTF_DEFINE_UTEST_PRE(param_test, roundup_pow2, test_pre)
{
    merr_t err;

    /* clang-format off */
    err = check(
        "test_uint32a=9223372036854775807", false,
        "test_uint32a=hello", false,
        "test_uint32a=-1", false,
        "test_uint32a=2000", true,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(2048, params.test_uint32a);
}

MTF_DEFINE_UTEST_PRE(param_test, jsonify, test_pre)
{
    char *str;
    cJSON *root;

    root = params_to_json(&params, NELEM(pspecs), pspecs);
    ASSERT_NE(NULL, root);

    str = cJSON_PrintUnformatted(root);
    ASSERT_NE(NULL, str);

    cJSON_Delete(root);

    ASSERT_STREQ(
        "{\"test1\":true,"
        "\"test_uint8\":2,"
        "\"test_uint16\":3,"
        "\"test_uint32\":4,"
        "\"test_uint64\":5,"
        "\"test_size\":6,"
        "\"test_int\":6,"
        "\"test_int8\":7,"
        "\"test_int16\":8,"
        "\"test_int32\":9,"
        "\"test_int64\":10,"
        "\"test_string\":\"default\","
        "\"test_array\":[{\"field1\":5},{\"field1\":5}],"
        "\"test_uint64a\":4,"
        "\"test_uint64b\":4,"
        "\"test_uint64c\":4,"
        "\"test_uint64d\":4,"
        "\"test_uint32a\":1000,"
        "\"test_double\":0.5}",
        str);

    free(str);
}

MTF_DEFINE_UTEST_PRE(param_test, get, test_pre)
{
    merr_t err;
    char buf[128];
    size_t needed_sz;

    err = params_get(&params, NELEM(pspecs), pspecs, "test1", buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_STREQ("true", buf);
    ASSERT_EQ(4, needed_sz);

    err = params_get(&params, NELEM(pspecs), pspecs, "test1", buf, sizeof(buf), NULL);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_STREQ("true", buf);

    err = params_get(&params, NELEM(pspecs), pspecs, "does.not.exist", buf, sizeof(buf), NULL);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = params_get(NULL, NELEM(pspecs), pspecs, "test1", buf, sizeof(buf), NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = params_get(&params, NELEM(pspecs), NULL, "test1", buf, sizeof(buf), NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = params_get(&params, NELEM(pspecs), pspecs, NULL, buf, sizeof(buf), NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = params_get(&params, NELEM(pspecs), pspecs, "test1", NULL, 0, &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(4, needed_sz);
}

MTF_DEFINE_UTEST_PRE(param_test, set, test_pre)
{
    merr_t err;

    ASSERT_TRUE(params.test1); /* default value */
    err = params_set(&params, sizeof(params), NELEM(pspecs), pspecs, "test1", "false");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_FALSE(params.test1);

    /* Test not WRITABLE */
    err = params_set(&params, sizeof(params), NELEM(pspecs), pspecs, "test_uint16", "10");
    ASSERT_EQ(EROFS, merr_errno(err));
    ASSERT_EQ(3, params.test_uint16); /* value set from above */

    /* Fail to parse */
    err = params_set(&params, sizeof(params), NELEM(pspecs), pspecs, "test1", "invalid");
    ASSERT_EQ(EINVAL, merr_errno(err));
    ASSERT_FALSE(params.test1); /* value set from above */

    /* Fail to convert */
    err = params_set(&params, sizeof(params), NELEM(pspecs), pspecs, "test_uint8", "\"convert\"");
    ASSERT_EQ(EINVAL, merr_errno(err));
    ASSERT_EQ(2, params.test_uint8); /* default value */

    /* Fail to validate */
    err = params_set(&params, sizeof(params), NELEM(pspecs), pspecs, "test_uint32a", "65536");
    ASSERT_EQ(EINVAL, merr_errno(err));
    ASSERT_EQ(1000, params.test_uint32a); /* default value */

    /* Fail to validate relationships */
    err = params_set(&params, sizeof(params), NELEM(pspecs), pspecs, "test_uint32a", "1");
    ASSERT_EQ(EINVAL, merr_errno(err));
    ASSERT_EQ(1000, params.test_uint32a); /* default value */
}

MTF_DEFINE_UTEST(param_test, from_paramv_malformed_kv_pair)
{
    merr_t err;
    const char *paramv[] = { "test_uint8", "test_uint8=" };

    err = params_from_paramv(&params, 1, paramv, NELEM(pspecs), pspecs);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = params_from_paramv(&params, 1, paramv + 1, NELEM(pspecs), pspecs);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(param_test, from_paramv_invalid_param)
{
    merr_t err;
    const char *paramv[] = { "invalid=0" };

    err = params_from_paramv(&params, 1, paramv, NELEM(pspecs), pspecs);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(param_test, from_paramv_invalid_value)
{
    merr_t err;
    const char *paramv[] = { "test_uint8=-1" };

    err = params_from_paramv(&params, 1, paramv, NELEM(pspecs), pspecs);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(param_test, from_paramv)
{
    merr_t err;
    const char *paramv[] = { "test_uint8=7" };

    err = params_from_paramv(&params, NELEM(paramv), paramv, NELEM(pspecs), pspecs);
    ASSERT_EQ(0, err);
    ASSERT_EQ(7, params.test_uint8);
}

MTF_DEFINE_UTEST(param_test, from_paramv_overwrite)
{
    merr_t err;
    const char *paramv[] = { "test_uint8=8", "test_uint8=7" };

    err = params_from_paramv(&params, NELEM(paramv), paramv, NELEM(pspecs), pspecs);
    ASSERT_EQ(0, err);
    ASSERT_EQ(7, params.test_uint8);
}

MTF_END_UTEST_COLLECTION(param_test)
