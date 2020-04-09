/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_C0SKM_H
#define HSE_CORE_C0SKM_H

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/rcu.h>
#include <hse_util/mutex.h>

#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/kvdb_health.h>

struct c0sk;
struct kvdb_rparams;
struct kvset_builder;
struct c1;
struct throttle_sensor;

/* MTF_MOCK_DECL(c0skm) */

/**
 * c0skm_open() - Initialize c0sk mutation.
 * @handle:    c0sk handle
 * @rp:        kvdb rparam
 * @c1h:       c1 handle
 * mpname:     mpool name
 */
/* MTF_MOCK */
merr_t
c0skm_open(struct c0sk *handle, struct kvdb_rparams *rp, struct c1 *c1h, const char *mpname);

/**
 * c0skm_close() - Close the c0sk mutation handle and destroy it.
 * @handle: c0sk handle
 */
/* MTF_MOCK */
void
c0skm_close(struct c0sk *handle);

/**
 * c0skm_flush() - Start ingest of existing c0sk mutation data
 * @self: Instance of struct c0sk to flush
 */
/* MTF_MOCK */
merr_t
c0skm_flush(struct c0sk *self);

/**
 * c0skm_sync() - Force immediate ingest of existing c0sk mutation data
 * @self:       Instance of struct c0sk to flush
 */
/* MTF_MOCK */
merr_t
c0skm_sync(struct c0sk *self);

/**
 * c0skm_set_tseqno() - Set the last committed transaction seq. no.
 * @handle: c0sk handle
 * @seqno:  sequence number
 */
void
c0skm_set_tseqno(struct c0sk *handle, u64 seqno);

/**
 * c0skm_bldr_get() - get builder from c0skm/c1
 * @self:             Instance of struct c0sk to flush
 * @gen:              kvms gen number
 * @bldrout:          kvset builder
 */
/* MTF_MOCK */
merr_t
c0skm_bldr_get(struct c0sk *self, u64 gen, struct kvset_builder ***bldrout);

/* MTF_MOCK */
void
c0skm_bldr_put(struct c0sk *self, u64 gen, u64 c0vlen, u64 c1vlen);

/**
 * c0skm_dtime_throttle_sensor() - Initialize c0skm dtime throttling
 * @handle:    c0sk handle
 * @sensor:    throttle sensor
 */
/* MTF_MOCK */
void
c0skm_dtime_throttle_sensor(struct c0sk *handle, struct throttle_sensor *sensor);

/**
 * c0skm_dsize_throttle_sensor() - Initialize c0skm dsize throttling
 * @handle:    c0sk handle
 * @sensor:    throttle sensor
 */
/* MTF_MOCK */
void
c0skm_dsize_throttle_sensor(struct c0sk *handle, struct throttle_sensor *sensor);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "c0skm_ut.h"
#endif

#endif /* HSE_CORE_C0SKM_H */
