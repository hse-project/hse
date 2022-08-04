#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.

#doc: test for complete annihilation during spills when tombs delete all existing keys

. common.subr

trap kvdb_drop EXIT
kvdb_create

keys=10

kvs=$(kvs_create smoke-0)

# Set rspill params to 0x0404 (min/max of 4/4) so that we generate
# two cn root spills for each group of eight calls to putbin.
#
parms=(kvdb-oparms csched_rspill_params=$((0x0404)) csched_debug_mask=$((0xffff)) kvs-oparms cn_close_wait=true)

# Generate 8 kvsets in root node, with distinct keys
for ((i = 0; i < 8; i++)); do
    cmd putbin -s$((i*keys)) "-c$keys" "$home" "$kvs" "${parms[@]}" cn_maint_disable=true
done

# for troubleshooting
cmd pscan -x "$home" "$kvs"
cmd cn_metrics "$home" "$kvs"

# Let compaction run, which should spill all keys into level 1
cmd putbin -n 5000 "$home" "$kvs" "${parms[@]}"
cmd putbin -n 5000 "$home" "$kvs" "${parms[@]}"

# for troubleshooting
cmd pscan -x "$home" "$kvs"
cmd cn_metrics "$home" "$kvs"

# verify no kvsets in level 0
cmd cn_metrics "$home" "$kvs" | cmd -e grep -P '^k\s+0\s0\s'

# Repeat putbin, but with -D to add tombstones
for ((i = 0; i < 8; i++)); do
    cmd putbin -D -s$((i*keys)) "-c$keys" "$home" "$kvs" "${parms[@]}" cn_maint_disable=true
done

# for troubleshooting
cmd pscan -x "$home" "$kvs"
cmd cn_metrics "$home" "$kvs"

# verify no keys
cmd pscan -c "$home" "$kvs"
