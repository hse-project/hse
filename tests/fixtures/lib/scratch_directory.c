/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <errno.h>
#include <ftw.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <hse/error/merr.h>
#include <hse/test/fixtures/scratch_directory.h>

static pid_t process;
static char *scratch_directory_copy;

static int
remove_cb(
    const char *const fpath,
    const struct stat *const sb,
    int typeflag,
    struct FTW *const ftwbuf)
{
    remove(fpath);
    return 0;
}

static void
cleanup()
{
    /* We ignore SIGCHLD below, but atexit(3) handlers can still be called upon
     * a fork(2) for instance.
     */
    if (process != getpid())
        return;

    nftw(scratch_directory_copy, remove_cb, 1, FTW_DEPTH | FTW_MOUNT | FTW_PHYS);
    free(scratch_directory_copy);
    scratch_directory_copy = NULL;
}

merr_t
scratch_directory_setup(const char *const ident, char *const buf, const size_t buf_sz)
{
    int rc;
    const char *parent;

    if (scratch_directory_copy || (buf && buf[0] != '\0'))
        return 0;

    parent = getenv("HSE_TEST_RUNNER_DIR");
    if (parent)
        goto touch;
    parent = getenv("MESON_BUILD_ROOT");
    if (parent)
        goto touch;
    parent = "/tmp";

touch:
    if (parent[0] == '\0')
        return merr(EINVAL);

    rc = snprintf(buf, buf_sz, "%s%smtest-%s-XXXXXX",
        parent, parent[strlen(parent) - 1] == '/' ? "" : "/", ident);
    if (rc >= buf_sz) {
        return merr(ENAMETOOLONG);
    } else if (rc < 0) {
        return merr(EBADMSG);
    }

    if (!mkdtemp(buf))
        return merr(errno);

    scratch_directory_copy = strdup(buf);
    if (!scratch_directory_copy)
        return merr(ENOMEM);

    atexit(cleanup);
    for (int i = 0; i < NSIG; i++) {
        struct sigaction nact = { 0 };

        switch (i) {
        /* Ignore when child processes exit. */
        case SIGCHLD:
            continue;
        default:
            sigemptyset(&nact.sa_mask);
            nact.sa_handler = cleanup;

            sigaction(i, &nact, NULL);
            break;
        }
    }

    process = getpid();

    return 0;
}
