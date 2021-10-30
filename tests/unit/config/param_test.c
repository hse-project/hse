/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_ikvdb/param.h>
#include <hse_util/storage.h>

struct test_arr_type {
    int8_t field1;
};

struct test_params {
    bool                 test1;
    uint8_t              test2;
    uint16_t             test3;
    uint32_t             test4;
    uint64_t             test5;
    int8_t               test6;
    int16_t              test7;
    int32_t              test8;
    int64_t              test9;
    char                 test10[12];
    struct test_arr_type test11[2];

    uint64_t test12;
    uint64_t test13;
    uint64_t test14;
    uint64_t test15;

    uint32_t test16;
} params;

merr_t
argv_deserialize_to_params(
    const size_t             paramc,
    const char *const *      paramv,
    const size_t             pspecs_sz,
    const struct param_spec *pspecs,
    const struct params *    params);

bool
array_converter(const struct param_spec *const ps, const cJSON *const node, void *const data)
{
    int                   i = 0;
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
array_validator(const struct param_spec *const ps, const void *const data)
{
    const struct test_arr_type *arr = data;

    return arr[0].field1 < 10 && arr[1].field1 < 10;
}

void
array_default_builder(const struct param_spec *const ps, void *const data)
{
    struct test_arr_type *arr = data;

    arr[0].field1 = 5;
    arr[1].field1 = 6;
}

bool
array_relation_validate(const struct param_spec *const ps, const struct params *p)
{
    struct test_params *params = p->p_params.as_generic;

    return params->test11[0].field1 < params->test9 && params->test11[1].field1 < params->test8;
}

const struct param_spec pspecs[] = {
	{
		.ps_name = "test1",
		.ps_description = "test1",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_BOOL,
		.ps_offset = offsetof(struct test_params, test1),
		.ps_size = PARAM_SZ(struct test_params, test1),
		.ps_convert = param_default_converter,
		.ps_validate = param_default_validator,
		.ps_default_value = {
			.as_bool = true,
		},
	},
	{
		.ps_name = "test2",
		.ps_description = "test2",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_U8,
		.ps_offset = offsetof(struct test_params, test2),
		.ps_size = PARAM_SZ(struct test_params, test2),
		.ps_convert = param_default_converter,
		.ps_validate = param_default_validator,
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
		.ps_name = "test3",
		.ps_description = "test3",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_U16,
		.ps_offset = offsetof(struct test_params, test3),
		.ps_size = PARAM_SZ(struct test_params, test3),
		.ps_convert = param_default_converter,
		.ps_validate = param_default_validator,
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
		.ps_name = "test4",
		.ps_description = "test4",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_U32,
		.ps_offset = offsetof(struct test_params, test4),
		.ps_size = PARAM_SZ(struct test_params, test4),
		.ps_convert = param_default_converter,
		.ps_validate = param_default_validator,
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
		.ps_name = "test5",
		.ps_description = "test5",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_U64,
		.ps_offset = offsetof(struct test_params, test5),
		.ps_size = PARAM_SZ(struct test_params, test5),
		.ps_convert = param_default_converter,
		.ps_validate = param_default_validator,
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
		.ps_name = "test6",
		.ps_description = "test6",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_I8,
		.ps_offset = offsetof(struct test_params, test6),
		.ps_size = PARAM_SZ(struct test_params, test6),
		.ps_convert = param_default_converter,
		.ps_validate = param_default_validator,
		.ps_default_value = {
			.as_scalar = 6,
		},
		.ps_bounds = {
			.as_scalar = {
				.ps_min = INT8_MIN,
				.ps_max = INT8_MAX,
			},
		},
	},
	{
		.ps_name = "test7",
		.ps_description = "test7",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_I16,
		.ps_offset = offsetof(struct test_params, test7),
		.ps_size = PARAM_SZ(struct test_params, test7),
		.ps_convert = param_default_converter,
		.ps_validate = param_default_validator,
		.ps_default_value = {
			.as_scalar = 7,
		},
		.ps_bounds = {
			.as_scalar = {
				.ps_min = INT16_MIN,
				.ps_max = INT16_MAX,
			},
		},
	},
	{
		.ps_name = "test8",
		.ps_description = "test8",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_I32,
		.ps_offset = offsetof(struct test_params, test8),
		.ps_size = PARAM_SZ(struct test_params, test8),
		.ps_convert = param_default_converter,
		.ps_validate = param_default_validator,
		.ps_default_value = {
			.as_scalar = 8,
		},
		.ps_bounds = {
			.as_scalar = {
				.ps_min = INT32_MIN,
				.ps_max = INT32_MAX,
			},
		},
	},
	{
		.ps_name = "test9",
		.ps_description = "test9",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_I64,
		.ps_offset = offsetof(struct test_params, test9),
		.ps_size = PARAM_SZ(struct test_params, test9),
		.ps_convert = param_default_converter,
		.ps_validate = param_default_validator,
		.ps_default_value = {
			.as_scalar = 9,
		},
		.ps_bounds = {
			.as_scalar = {
				.ps_min = INT64_MIN,
				.ps_max = INT64_MAX,
			},
		},
	},
	{
		.ps_name = "test10",
		.ps_description = "test10",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_STRING,
		.ps_offset = offsetof(struct test_params, test10),
		.ps_convert = param_default_converter,
		.ps_validate = param_default_validator,
		.ps_default_value = {
			.as_string = "default",
		},
		.ps_bounds = {
			.as_string = {
				.ps_max_len = PARAM_SZ(struct test_params, test10),
			},
		},
	},
	{
		.ps_name = "test11",
		.ps_description = "test11",
		.ps_flags = PARAM_FLAG_DEFAULT_BUILDER,
		.ps_type = PARAM_TYPE_ARRAY,
		.ps_offset = offsetof(struct test_params, test11),
		.ps_convert = array_converter,
		.ps_validate = array_validator,
		.ps_validate_relations = array_relation_validate,
		.ps_default_value = {
			.as_builder = array_default_builder,
		},
	},
	{
		.ps_name = "test12",
		.ps_description = "test12",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_U64,
		.ps_offset = offsetof(struct test_params, test12),
		.ps_size = PARAM_SZ(struct test_params, test12),
		.ps_convert = param_convert_to_bytes_from_KB,
		.ps_validate = param_default_validator,
		.ps_default_value = {
			.as_uscalar = 4,
		},
		.ps_bounds = {
			.as_uscalar = {
				.ps_min = 0,
				.ps_max = UINT64_MAX,
			},
		},
	},
	{
		.ps_name = "test13",
		.ps_description = "test13",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_U64,
		.ps_offset = offsetof(struct test_params, test13),
		.ps_size = PARAM_SZ(struct test_params, test13),
		.ps_convert = param_convert_to_bytes_from_MB,
		.ps_validate = param_default_validator,
		.ps_default_value = {
			.as_uscalar = 1000,
		},
		.ps_bounds = {
			.as_uscalar = {
				.ps_min = 0,
				.ps_max = UINT64_MAX,
			},
		},
	},
	{
		.ps_name = "test14",
		.ps_description = "test14",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_U64,
		.ps_offset = offsetof(struct test_params, test14),
		.ps_size = PARAM_SZ(struct test_params, test14),
		.ps_convert = param_convert_to_bytes_from_GB,
		.ps_validate = param_default_validator,
		.ps_default_value = {
			.as_uscalar = 1000,
		},
		.ps_bounds = {
			.as_uscalar = {
				.ps_min = 0,
				.ps_max = UINT64_MAX,
			},
		},
	},
	{
		.ps_name = "test15",
		.ps_description = "test15",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_U64,
		.ps_offset = offsetof(struct test_params, test15),
		.ps_size = PARAM_SZ(struct test_params, test15),
		.ps_convert = param_convert_to_bytes_from_TB,
		.ps_validate = param_default_validator,
		.ps_default_value = {
			.as_uscalar = 1000,
		},
		.ps_bounds = {
			.as_uscalar = {
				.ps_min = 0,
				.ps_max = UINT64_MAX,
			},
		},
	},
    {
        .ps_name = "test16",
        .ps_description = "test16",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct test_params, test16),
        .ps_size = PARAM_SZ(struct test_params, test16),
        .ps_convert = param_roundup_pow2,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 1000,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            },
        },
    },
};

int
test_pre(struct mtf_test_info *ti)
{
    const struct params p = { .p_type = PARAMS_GEN, .p_params = { .as_generic = &params } };

    param_default_populate(pspecs, NELEM(pspecs), &p);

    return 0;
}

/**
 * Check the validity of various key=value combinations
 */
merr_t HSE_SENTINEL
check(const char *const arg, ...)
{
    merr_t      err;
    bool        success;
    const char *a = arg;
    va_list     ap;

    const struct params p = { .p_type = PARAMS_GEN, .p_params = { .as_generic = &params } };

    assert(arg);

    va_start(ap, arg);

    do {
        const char * paramv[] = { a };
        const size_t paramc = NELEM(paramv);

        success = !!va_arg(ap, int);

        err = argv_deserialize_to_params(paramc, paramv, NELEM(pspecs), pspecs, &p);

        if (success != !err) {
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
    ASSERT_EQ(2, params.test2);
    ASSERT_EQ(3, params.test3);
    ASSERT_EQ(4, params.test4);
    ASSERT_EQ(5, params.test5);
    ASSERT_EQ(6, params.test6);
    ASSERT_EQ(7, params.test7);
    ASSERT_EQ(8, params.test8);
    ASSERT_EQ(9, params.test9);
    ASSERT_STREQ("default", params.test10);
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_bool, test_pre)
{
    merr_t err;

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

    /* clang-format off */
	err = check(
		"test2=12", true,
		"test2=-1", false,
		"test2=257", false,
		"test2=1.5", false,
		"test2=wrong", false,
		NULL
	);
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_u16, test_pre)
{
    merr_t err;

    /* clang-format off */
	err = check(
		"test3=12", true,
		"test3=-1", false,
		"test3=65537", false,
		"test3=1.5", false,
		"test3=wrong", false,
		NULL
	);
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_u32, test_pre)
{
    merr_t err;

    /* clang-format off */
	err = check(
		"test4=12", true,
		"test4=-1", false,
		"test4=4294967297", false,
		"test4=1.5", false,
		"test4=wrong", false,
		NULL
	);
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_u64, test_pre)
{
    merr_t err;

    /* clang-format off */
	err = check(
		"test5=12", true,
		"test5=-1", false,
		"test5=18446744073709551616", false,
		"test5=1.5", false,
		"test5=wrong", false,
		NULL
	);
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_i8, test_pre)
{
    merr_t err;

    /* clang-format off */
	err = check(
		"test6=12", true,
		"test6=-129", false,
		"test6=128", false,
		"test6=1.5", false,
		"test6=wrong", false,
		NULL
	);
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_i16, test_pre)
{
    merr_t err;

    /* clang-format off */
	err = check(
		"test7=12", true,
		"test7=-32769", false,
		"test7=32768", false,
		"test7=1.5", false,
		"test7=wrong", false,
		NULL
	);
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_i32, test_pre)
{
    merr_t err;

    /* clang-format off */
	err = check(
		"test8=12", true,
		"test8=-2147483648", false,
		"test8=2147483648", false,
		"test8=1.5", false,
		"test8=wrong", false,
		NULL
	);
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_i64, test_pre)
{
    merr_t err;

    /* clang-format off */
	err = check(
		"test9=12", true,
		"test9=-9223372036854775808", false,
		"test9=9223372036854775808", false,
		"test9=1.5", false,
		"test9=wrong", false,
		NULL
	);
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_string, test_pre)
{
    merr_t err;

    /* clang-format off */
	err = check(
		"test10=yes", true,
		"test10=\"yes\"", true,
		"test10=this-is-a-long-string-please-fail", false,
		"test10=false", false,
		NULL
	);
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, param_type_array, test_pre)
{
    merr_t err;

    /* clang-format off */
	err = check(
		"test11=[{\"field1\": 0}, {\"field1\": 1}]", true,
		"test11=[{\"field1\": 0}, {\"field1\": 11}]", false,
		"test11=false", false,
		NULL
	);
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(param_test, to_bytes_from_KB, test_pre)
{
    merr_t err;

    /* clang-format off */
    err = check(
		"test12=5", true,
		"test12=hello", false,
		NULL
	);
	/* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(5 * KB, params.test12);
}

MTF_DEFINE_UTEST_PRE(param_test, to_bytes_from_MB, test_pre)
{
    merr_t err;

    /* clang-format off */
    err = check(
		"test13=5", true,
		"test13=hello", false,
		NULL
	);
	/* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(5 * MB, params.test13);
}

MTF_DEFINE_UTEST_PRE(param_test, to_bytes_from_GB, test_pre)
{
    merr_t err;

    /* clang-format off */
    err = check(
		"test14=5", true,
		"test14=hello", false,
		NULL
	);
	/* clang-format on */

	ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(5 * GB, params.test14);
}

MTF_DEFINE_UTEST_PRE(param_test, to_bytes_from_TB, test_pre)
{
    merr_t err;

	/* clang-format off */
    err = check(
		"test15=5", true,
		"test15=hello", false,
		NULL
	);
	/* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(5 * TB, params.test15);
}

MTF_DEFINE_UTEST_PRE(param_test, roundup_pow2, test_pre)
{
    merr_t err;

    /* clang-format off */
    err = check(
        "test16=9223372036854775807", false,
        "test16=hello", false,
        "test16=-1", false,
        "test16=2000", true,
        NULL
    );
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(2048, params.test16);
}

MTF_END_UTEST_COLLECTION(param_test)
