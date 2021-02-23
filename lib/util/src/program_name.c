/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/string.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>
#include <hse_util/program_name.h>

#define PROGNAMSZ 64

merr_t
hse_program_name(char **name, char **base)
{
    ssize_t rc2 = 1;
    size_t  sz = 0;
    merr_t  err = 0;

    if (!name || *name)
        return merr(ev(EINVAL));

    /* guess/resize because lstat(2) gives st_size=0 for "/proc/self/exe" */
    for (sz = PROGNAMSZ, rc2 = 1; rc2 >= 0; sz += PROGNAMSZ) {
        void *p;

        p = realloc(*name, sz + 1);
        if (!p) {
            free(*name);
            return merr(ev(ENOMEM));
        }
        *name = p;
        memset(*name, 0, sz + 1);
        strlcpy(*name, "unavailable", sz);

        rc2 = readlink("/proc/self/exe", *name, sz);
        if (rc2 < 0) {
            err = merr(ev(errno));
            break;
        }

        (*name)[rc2] = 0; /* Coverity insists */

        /* It's important to terminate the loop if rc2 is zero */
        if (rc2 < sz) {
            if (base) {
                *base = strrchr(*name, '/');
                *base = *base ? *base + 1 : *name;
            }
            return 0;
        }
    }

    free(*name);
    return err;
}
