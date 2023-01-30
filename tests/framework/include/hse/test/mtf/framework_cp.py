# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2015 Micron Technology, Inc. All rights reserved.
#

#
# The HSE Unit Test Framework includes the functionality of allowing a unit
# test to be defined in which a given test function will be called repeatedly
# with arguments spanning the cross product of N discrete sets where N
# is in the range [1-10].
#
# The CPP macros to enable this have a highly regular structure but are
# large (e.g., the 10-dimensional code is ~200 lines). To reduce the
# possibility of typos and to ease maintenance of the code, the following
# Python script was written that generates a header file with the correct
# CPP macros.
#

preamble_text = """/*
 * Copyright (C) 2015 Micron Technology, Inc. All rights reserved.
 */

#ifndef HSE_UTEST_FRAMEWORK_CP_H
#define HSE_UTEST_FRAMEWORK_CP_H

/*
 * !!! WARNING !!!
 *
 * This file is generated from the Python script "framework_cp.py". If you
 * think you want to change this file, change the script and regenerate this
 * file from the updated script.
 */
"""


def print_preamble():
    print(preamble_text)


def print_postamble():
    print("#endif")


def print_with_cont(iostr, interior):
    print(iostr, end="")
    if interior:
        tp = len(iostr)
        print("{:>{width}}".format(" ", width=(78 - tp)), end="")
        print("\\")
    else:
        print("")


def print_stvtv(N, last):
    N_str = "st{0}, vt{0}, v{0}"
    if last:
        suffix = ")"
    else:
        suffix = ","
    print(N_str.format(N) + suffix, end="")


def print_stvtv_tuples(N):
    for i in range(N - 1):
        print_stvtv(i, False)
    print_stvtv(N - 1, True)


def print_mtf_value_declare(N, interior):
    N_str = "    ___MTF_VALUE_DECLARE({0}, vt{0}, v{0})"
    print_with_cont(N_str.format(N), interior)


def print_mtf_value_declare_rows(N, interior):
    for i in range(N - 1):
        print_mtf_value_declare(i, True)
    print_mtf_value_declare(N - 1, interior)


def print_mtf_call_generator(N, interior):
    N_str = "    ___MTF_CALL_GENERATOR(v{0})"
    print_with_cont(N_str.format(N), interior)


def print_mtf_call_generator_rows(N, interior):
    for i in range(N - 1):
        print_mtf_call_generator(i, True)
    print_mtf_call_generator(N - 1, interior)


def print_mtf_dimension(N, pad, interior):
    N_str = (
        "    "
        + pad
        + "for (index{0} = 0; index{0} < ___mtf_##v{0}##_length; "
        + "++index{0}) {{"
    )
    print_with_cont(N_str.format(N), True)
    N_str = "        " + pad + "v{0} = ___mtf_##v{0}##_values[index{0}];"
    print_with_cont(N_str.format(N), interior)


def print_mtf_dimension_rows(N, interior):

    for i in range(N - 1):
        pad = "{:>{width}}".format("", width=i)
        print_mtf_dimension(i, pad, True)
    pad = "{:>{width}}".format("", width=N - 1)
    print_mtf_dimension(N - 1, pad, interior)


def print_begin_cpN(N):
    N_str = "#define ___MTF_INNER_DEFINE_UTEST_CP{0}(coll_name, test_name, "
    print(N_str.format(N), end="")
    N_str = "pre_hook, post_hook, "
    print(N_str.format(N), end="")
    print_stvtv_tuples(N)
    print("\\")
    iostr = "___MTF_INNER_DEFINE_UTEST(coll_name, test_name, " + "pre_hook, post_hook)"
    print_with_cont(iostr, True)
    print_with_cont("{", True)
    print_with_cont("", True)
    print_mtf_value_declare_rows(N, True)
    print_with_cont("", True)
    print_mtf_call_generator_rows(N, True)
    print_with_cont("", True)
    print_with_cont("  early_return_check:", True)
    print_with_cont("    if (!lcl_ti->ti_status) {", True)
    print_with_cont("        return;", True)
    print_with_cont("    }", True)
    print_with_cont("", True)
    print_mtf_dimension_rows(N, False)


def print_cpN_wrappers(N):
    pre_str_1 = "#define MTF_DEFINE_UTEST_CP{}".format(N)
    pre_str_2 = "___MTF_INNER_DEFINE_UTEST_CP{}".format(N)

    iostr = pre_str_1 + "(coll_name, test_name, "
    print(iostr, end="")
    print_stvtv_tuples(N)
    print("\\")
    iostr = pre_str_2 + "(coll_name, test_name, 0, 0, "
    print(iostr, end="")
    print_stvtv_tuples(N)
    print()

    print("")
    iostr = pre_str_1 + "_PRE(coll_name, test_name, pre_hook,"
    print(iostr, end="")
    print_stvtv_tuples(N)
    print("\\")
    iostr = pre_str_2 + "(coll_name, test_name, pre_hook, 0,"
    print(iostr, end="")
    print_stvtv_tuples(N)
    print()

    print("")
    iostr = pre_str_1 + "_POST(coll_name, test_name, post_hook,"
    print(iostr, end="")
    print_stvtv_tuples(N)
    print("\\")
    iostr = pre_str_2 + "(coll_name, test_name, 0, post_hook,"
    print(iostr, end="")
    print_stvtv_tuples(N)
    print()

    print("")
    iostr = pre_str_1 + "_PREPOST(coll_name, test_name, pre_hook, post_hook,"
    print(iostr, end="")
    print_stvtv_tuples(N)
    print("\\")
    iostr = pre_str_2 + "(coll_name, test_name, pre_hook, post_hook,"
    print(iostr, end="")
    print_stvtv_tuples(N)


def print_end_cpN(N):
    print_with_cont("#define MTF_END_CP{}".format(N), True)
    for i in range(N, 0, -1):
        offset = 2 * i
        iostr = "{:>{width}}".format("}", width=offset + 1)
        print_with_cont(iostr, True)
    iostr = "{:>{width}}".format("}", width=1)
    print_with_cont(iostr, False)


def main():
    cmnt_str = "/* " + "{:->{width}}".format("-", width=73) + " */"

    print_preamble()

    for dimensions in range(1, 11):
        #    for dimensions in range(1, 2):
        print(cmnt_str)
        print("\n", end="")
        print_begin_cpN(dimensions)
        print("\n\n", end="")
        print_cpN_wrappers(dimensions)
        print("\n\n", end="")
        print_end_cpN(dimensions)
        print("\n", end="")
        print(cmnt_str)

    print_postamble()


main()
