/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/time.h>

void
time_to_tm(time_t totalsecs, int offset, struct tm *result)
{
    totalsecs += offset;

    gmtime_r(&totalsecs, result);
}
