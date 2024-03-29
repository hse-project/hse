/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_PFXLOCK_H
#define HSE_KVDB_PFXLOCK_H

#include <stdint.h>

#include <hse/error/merr.h>

#include "kvdb/kvdb_pfxlock.h"

struct kvdb_ctxn_pfxlock;
struct kvdb_pfxlock;

merr_t
kvdb_ctxn_pfxlock_init(void) HSE_COLD;

void
kvdb_ctxn_pfxlock_fini(void) HSE_COLD;

merr_t
kvdb_ctxn_pfxlock_create(
    struct kvdb_pfxlock *kvdb_pfxlock,
    uint64_t view_seqno,
    struct kvdb_ctxn_pfxlock **kpl_out);

void
kvdb_ctxn_pfxlock_destroy(struct kvdb_ctxn_pfxlock *kpl);

merr_t
kvdb_ctxn_pfxlock_shared(struct kvdb_ctxn_pfxlock *kpl, uint64_t hash);

merr_t
kvdb_ctxn_pfxlock_excl(struct kvdb_ctxn_pfxlock *kpl, uint64_t hash);

void
kvdb_ctxn_pfxlock_seqno_pub(struct kvdb_ctxn_pfxlock *kpl, uint64_t end_seqno);

#endif
