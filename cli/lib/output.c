/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2023 Micron Technology, Inc.
 */

#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>

#include <hse/hse.h>

#include <hse/cli/output.h>
#include <hse/cli/program.h>
#include <hse/util/compiler.h>

static thread_local char error_buffer_tls[1024];

static void
eprint(const hse_err_t err, const char *fmt, va_list ap)
{
    int rc HSE_MAYBE_UNUSED;

    /* We take progname from argv[0]. argv[0] may contain % symbols which could
     * cause an escape in the vfprintf() below, so just print it plainly for
     * safety.
     */
    fputs(progname, stderr);
    if (err) {
        char buf[256];
        size_t needed_sz HSE_MAYBE_UNUSED;

        needed_sz = hse_strerror(err, buf, sizeof(buf));
        assert(needed_sz < sizeof(buf));

        rc = snprintf(error_buffer_tls, sizeof(error_buffer_tls), ": %s: %s\n", fmt, buf);
    } else {
        rc = snprintf(error_buffer_tls, sizeof(error_buffer_tls), ": %s\n", fmt);
    }
    assert(rc >= 0 && rc < sizeof(error_buffer_tls));

    vfprintf(stderr, error_buffer_tls, ap);
}

void
error(const hse_err_t err, const char * const fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    eprint(err, fmt, ap);
    va_end(ap);
}

void
fatal(const hse_err_t err, const char * const fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    eprint(err, fmt, ap);
    va_end(ap);

    exit(1);
}

void
syntax(const char * const fmt, ...)
{
    va_list ap;
    char msg[256];

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    error(0, "%s, use -h for help", msg);
    exit(EX_USAGE);
}
