/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>

#define MTF_MOCK_IMPL_sos_log

#include "sos_log.h"
#include <hse_ikvdb/ikvdb.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

struct sos_log {
    int   sos_fd;
    uint  sos_file_entries;
    uint  sos_file_idx;
    char *sos_file_names[SOS_LOG_NUM_FILES];
};

static void
sos_log_next_file(struct sos_log *self)
{
    sos_log_close(self);
    self->sos_file_idx = (self->sos_file_idx + 1) % SOS_LOG_NUM_FILES;
    self->sos_file_entries = 0;
}

merr_t
sos_log_create(const char *mp_name, struct kvdb_rparams *rp, struct sos_log **out)
{
    struct sos_log *self;
    uint            i;
    size_t          flen;
    size_t          alen;

    /* Filename components:
     *    SOS_LOG_DIR  "/"  mp_name ".%u.sos"
     * Add strlens + 16 for the other bits and pieces
     * to get filename len.
     */
    flen = strlen(SOS_LOG_DIR) + strlen(mp_name) + 16;

    alen = sizeof(*self) + flen * SOS_LOG_NUM_FILES;

    self = malloc(alen);
    if (!self)
        return merr(ev(ENOMEM));

    self->sos_fd = -1;
    self->sos_file_entries = 0;
    self->sos_file_idx = 0;

    for (i = 0; i < SOS_LOG_NUM_FILES; i++) {
        self->sos_file_names[i] = (char *)(self + 1) + i * flen;
        snprintf(self->sos_file_names[i], flen, "%s/%s.%u.sos", SOS_LOG_DIR, mp_name, i);
    }

    *out = self;
    return 0;
}

void
sos_log_destroy(struct sos_log *self)
{
    if (self) {
        if (self->sos_fd != -1)
            close(self->sos_fd);
        free(self);
    }
}

merr_t
sos_log_open(struct sos_log *self)
{
    int         flags = O_WRONLY | O_CREAT | O_TRUNC;
    mode_t      mode = S_IRUSR | S_IWUSR | S_IRGRP;
    const char *file;

    if (self->sos_fd != -1)
        return 0;

    file = self->sos_file_names[self->sos_file_idx];
    self->sos_fd = open(file, flags, mode);
    if (self->sos_fd == -1)
        return merr_errno(errno);

    return 0;
}

void
sos_log_close(struct sos_log *self)
{
    if (self->sos_fd != -1) {
        close(self->sos_fd);
        self->sos_fd = -1;
    }
}

merr_t
sos_log_write(struct sos_log *self, void *data, size_t len)
{
    ssize_t rc;

    rc = write(self->sos_fd, data, len);
    if (rc == -1) {
        sos_log_next_file(self);
        return merr(errno);
    }

    self->sos_file_entries += 1;

    if (self->sos_file_entries >= SOS_LOG_ENTRIES_PER_FILE)
        sos_log_next_file(self);

    return 0;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "sos_log_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
