#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: verify tombstones in root node hide keys in level 1 (see SBUSWNF-1265/PR-672)

. common.subr

trap cleanup EXIT
kvdb_create

keys=10

kvs=$(kvs_create smoke-0)

# Set rspill params to 0x0404 (min/max of 4/4) so that we generate
# two cn root spills for each group of eight calls to putbin.
#
parms="kvdb-oparms csched_rspill_params=$((0x0404)) csched_debug_mask=$((0xffff))"

# Generate 8 kvsets in root node w/ duplicate data.
for ((i = 0; i < 8; i++)); do
    # shellcheck disable=SC2086
    cmd putbin "-c$keys" "$home" "$kvs" $parms kvs-oparms cn_maint_disable=true
done

# Let compaction run, which should spill all keys into level 1, then verify
# no kvsets in level 0
# shellcheck disable=SC2086
cmd putbin -n 1000 "$home" "$kvs" $parms kvs-oparms cn_close_wait=true
cmd cn_metrics "$home" "$kvs" | cmd -e grep -P '^k\s+0\s+0\s'

# Validate keys found in level 1, w/ maint disabled.
# shellcheck disable=SC2086
cmd putbin -V "-c$keys" "$home" "$kvs" $parms kvs-oparms cn_maint_disable=true

# Add tombstones, with maint disabled. Verify that one kvset is in root node.
# shellcheck disable=SC2086
cmd putbin -D "-c$keys" "$home" "$kvs" $parms kvs-oparms cn_maint_disable=true
cmd cn_metrics "$home" "$kvs" | cmd grep -P '^n\s+0\s+1\s'

# Validate keys, w/ maint disabled. Expect error since tombstones block.
# shellcheck disable=SC2086
cmd -e putbin -V -c1 "$home" "$kvs" $parms kvs-oparms cn_maint_disable=true
