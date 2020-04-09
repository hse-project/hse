/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_SOS_LOG_H
#define HSE_KVDB_SOS_LOG_H

#include <hse_util/hse_err.h>

struct kvdb_rparams;

/* MTF_MOCK_DECL(sos_log) */

#define SOS_LOG_DIR "/var/log/hse"
#define SOS_LOG_FILENAME_LEN_MAX 128
#define SOS_LOG_NUM_FILES 4
#define SOS_LOG_ENTRIES_PER_FILE 10

struct sos_log;

/* MTF_MOCK */
merr_t
sos_log_create(const char *mp_name, struct kvdb_rparams *rp, struct sos_log **out);

/* MTF_MOCK */
void
sos_log_destroy(struct sos_log *log);

/* MTF_MOCK */
merr_t
sos_log_open(struct sos_log *log);

/* MTF_MOCK */
void
sos_log_close(struct sos_log *log);

/* MTF_MOCK */
merr_t
sos_log_write(struct sos_log *log, void *data, size_t len);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "sos_log_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
