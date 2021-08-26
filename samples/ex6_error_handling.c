/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>

#include <hse/hse.h>

#include "helper.h"

/*
 * This example exists to merely show how errors can be handled in HSE
 * applications.
 *
 * Remember that hse_err_t is an integer which encodes various information about
 * the error. The most relevant part of hse_err_t for users will be the
 * encoded errno value. The actual value of the hse_err_t is not important,
 * other than check for a non-zero value.
 */

int
main(int argc, const char **argv)
{
    hse_err_t    err = 0;
    const char * paramv[] = { "logging.destination=stdout",
                             "logging.level=3",
                             "socket.enabled=false" };
    const size_t paramc = sizeof(paramv) / sizeof(paramv[0]);

    err = hse_init(NULL, paramc, paramv);
    if (err) {
        error(err, "Failed to initialize HSE");
        goto out;
    }

    /* NULL being passed to the handle is an error */
    err = hse_kvdb_open(NULL, 0, NULL, NULL);
    if (!err) {
        error(err, "Failed to receive error from bogus API call");
        goto out;
    }

    if (hse_err_to_errno(err) == EINVAL) {
        char   buf[256];
        size_t n;

        n = hse_strerror(err, buf, sizeof(buf));
        if (n >= sizeof(buf)) {
            fprintf(stderr, "Error message was truncated\n");
            err = ENAMETOOLONG;
            goto out;
        }

        printf("Correctly received a EINVAL for non-null argument: %s\n", buf);
    } else {
        fprintf(stderr, "Unexpected errno value: %d", hse_err_to_errno(err));
    }

out:
    hse_fini();

    return hse_err_to_errno(err);
}
