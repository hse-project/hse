#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.

#doc: test for complete annihilation during spills when tombs delete all existing keys

. common.subr

trap kvdb_drop EXIT
kvdb_create

keys=10

kvs=$(kvs_create smoke-0 fanout=2) || $?

sp='[[:space:]]'

# Set rspill params to 0x0404 (min/max of 4/4) so that we generate
# two cn root spills for each group of eight calls to putbin.
#
parms="kvdb-oparms csched_rspill_params=$((0x0404)) csched_debug_mask=$((0xffff)) kvs-oparms cn_close_wait=true"

set -x

# Generate 8 kvsets in root node, with distinct keys
for ((i = 0; i < 8; i++)); do
    # shellcheck disable=SC2086
    cmd putbin -s$((i*keys)) "-c$keys" "$home" "$kvs" $parms cn_maint_disable=true
done

# Let compaction run, which should spill all keys into level 1, then verify
# no kvsets in level 0
# shellcheck disable=SC2086
cmd putbin -n 5000 "$home" "$kvs" $parms
cmd putbin -n 5000 "$home" "$kvs" $parms
cmd cn_metrics "$home" "$kvs" | cmd -e grep -P "^k${sp}+0,0,0${sp}"

# Repeat putbin, but with -D to add tombstones
for ((i = 0; i < 8; i++)); do
    # shellcheck disable=SC2086
    cmd putbin -D -s$((i*keys)) "-c$keys" "$home" "$kvs" $parms cn_maint_disable=true
done

# Let compaction run, which should spill all keys into level 1, cause
# kv-compactions, key annihilation, and leave an empty tree.
# shellcheck disable=SC2086
cmd putbin -n 5000 "$home" "$kvs" $parms
cmd putbin -n 5000 "$home" "$kvs" $parms
cmd cn_metrics "$home" "$kvs" | cmd grep -P "^t${sp}+0,0,0${sp}"
