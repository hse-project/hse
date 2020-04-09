/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>

static int   pfd[2];
static FILE *saved_fp;

int
pipe_open(FILE **save)
{
    if (!save) {
        fprintf(stderr, "pipe_open requires save FILE **\n");
        return 1;
    }
    if (pipe(pfd)) {
        perror("pipe");
        return 1;
    }
    saved_fp = *save;
    *save = fdopen(pfd[1], "w");
    if (!*save) {
        *save = saved_fp;
        return 1;
    }
    return 0;
}

int
pipe_close(FILE **restore, char *find)
{
    char buf[4096];
    int  n;

    fflush(*restore);
    n = read(pfd[0], buf, sizeof(buf) - 1);
    if (n > 0)
        buf[n] = 0;
    close(pfd[0]);
    close(pfd[1]);
    *restore = saved_fp;
    saved_fp = 0;

    return n > 0 && (!find || strstr(buf, find));
}
