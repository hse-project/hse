/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/hse_err.h>

int
main(int argc, char **argv)
{
    struct merr_info info;
    merr_t           merr = strtoull(argc > 1 ? argv[1] : "0", 0, 0);

    printf("%lld: %s\n", (long long)merr, merr_info(merr, &info));
    return 0;
}
