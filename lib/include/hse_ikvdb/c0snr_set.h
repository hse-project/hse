/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C0SNR_SET_H
#define HSE_C0SNR_SET_H

#include <hse/util/platform.h>
#include <hse/util/event_counter.h>
#include <hse/util/atomic.h>

#define KVMS_GEN_INVALID             (~0UL)

struct kvdb_ctxn;
struct c0snr_set;

/**
 * c0snr_set_create() - create an allocator for C0SNRs
 * @handle:  (out) c0snr set handle
 */
merr_t
c0snr_set_create(struct c0snr_set **handle);

/**
 * c0snr_set_destroy() - destroy the C0SNR set
 * @handle: Instance of struct c0snr_set to destroy
 *
 */
void
c0snr_set_destroy(struct c0snr_set *handle);

/**
 * c0snr_set_get_c0snr() - get a C0SNR for a transaction
 * @handle: c0snr set handle
 * @txn:    client transaction handle (used during aborts)
 *
 */
void *
c0snr_set_get_c0snr(struct c0snr_set *handle, struct kvdb_ctxn *txn);

/**
 * c0snr_clear_txn() - clear the owner transaction handle
 * @priv:    c0snr
 *
 */
void
c0snr_clear_txn(uintptr_t *priv);

bool
c0snr_txn_is_active(uintptr_t *priv);

/**
 * c0snr_getref() - get a reference to the C0SNR during a put
 * @priv:     c0snr
 * @c0ms_gen: kvms generation number of the active KVMS
 *
 */
void
c0snr_getref(uintptr_t *priv, u64 c0ms_gen);

/**
 * c0snr_getref() - get KVMS generation of last put that used this C0SNR
 * @priv:     c0snr
 *
 */
u64
c0snr_get_cgen(uintptr_t *priv);

/**
 * c0snr_dropref() - drop the reference to this C0SNR
 * @priv:     c0snr
 *
 */
void
c0snr_dropref(uintptr_t *priv);

/**
 * c0snr_droprefv() - drop all references in the given vector of C0SNRs
 * @refc:  length of refv[]
 * @refv:  vector of references
 */
void
c0snr_droprefv(int refc, uintptr_t **refv);

#endif /* HSE_C0SNR_SET_H */
