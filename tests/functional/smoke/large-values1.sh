#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: kmt large value test (SBUSWNF-2165)

. common.subr

trap kvdb_drop EXIT
kvdb_create

kvs=$(kvs_create smoke-0) || exit $?

# This test depends on having 1MiB values in vblocks at offsets that are not
# page-aligned.  Using a small number of value lengths make that a frequent
# occurrence, thus exposing the bug (or verifying the fix) more likely.

VLEN=-l1048532:1048576

# Don't let the total size of the values exceed ~20G or 12.5% of available RAM,
# whichever is smaller.

KEYS=$(awk '/^MemAvail/ {printf "%lu", $2 / (1024 * 8)}' /proc/meminfo)
if ((KEYS > 20000)) ; then
   KEYS=20000
fi

kvs_oparams="kvs-oparams cn_maint_disable=true"

# ingest w spill disabled
# shellcheck disable=SC2086
cmd kmt "$home" "$kvs" -s1 "$VLEN" "-i$KEYS" $kvs_oparams

# verify no spill occurred
cmd cn_metrics "$home" "$kvs" | cmd -e grep -q n.1,

# verify keys and values
# shellcheck disable=SC2086
cmd kmt "$home" "$kvs" -s1 "$VLEN" -c $kvs_oparams

# spill
cmd putbin "$home" "$kvs" -n 1000 kvs-oparms cn_close_wait=true

# verify spill has occurred
cmd cn_metrics "$home" "$kvs" | cmd grep n.1,

# verify keys and values
# shellcheck disable=SC2086
cmd kmt "$home" "$kvs" -s1 "$VLEN" -c $kvs_oparams
