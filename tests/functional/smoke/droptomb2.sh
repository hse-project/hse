#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: test for complete annihilation during spills when tombs delete all existing keys

. "$(dirname "${BASH_SOURCE[0]}")/smoke.subr"

trap kvdb_drop EXIT
kvdb_create

keys=10

kvs=$(kvs_create smoke-0) || $?

sp='[[:space:]]'

parms='kvdb-oparms csched_debug_mask=0xffffffff kvs-oparms cn_close_wait=true'

# Generate 8 kvsets in root node, with distinct keys
for ((i = 0; i < 8; i++)); do
    # shellcheck disable=SC2086
    cmd putbin -s$((i*keys)) "-c$keys" "$home" "$kvs" $parms kvs-oparms cn_maint_disable=true
done

# Let compaction run, which should spill all keys into level 1, then verify
# no kvsets in level 0
# shellcheck disable=SC2086
cmd putbin -n 1000 "$home" "$kvs" kvs-oparms cn_close_wait=true $parms
cmd cn_metrics "$home" "$kvs" | cmd -e grep -P "^k${sp}+0,0,0${sp}"

# Repeat putbin, but with -D to add tombstones
for ((i = 0; i < 8; i++)); do
    # shellcheck disable=SC2086
    cmd putbin -D -s$((i*keys)) "-c$keys" "$home" "$kvs" $parms kvs-oparms cn_maint_disable=true
done

# Let compaction run, which should spill all keys into level 1, cause
# kv-compactions, key annihilation, and leave an empty tree.
# shellcheck disable=SC2086
cmd putbin -n 3000 "$home" "$kvs" $parms
cmd cn_metrics "$home" "$kvs" | cmd grep -P "^t${sp}+0,0,0${sp}"
