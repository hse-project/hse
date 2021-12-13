#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: verify tombstones in root node hide keys in level 1 (see SBUSWNF-1265/PR-672)

. common.subr

trap kvdb_drop EXIT
kvdb_create

keys=10

kvs=$(kvs_create smoke-0) || $?

sp='[[:space:]]'

kvdb_oparms='kvdb-oparms csched_debug_mask=0xffffffff'

# Generate 8 kvsets in root node w/ duplicate data.
for ((i = 0; i < 8; i++)); do
    # shellcheck disable=SC2086
    cmd putbin "-c$keys" "$home" "$kvs" $kvdb_oparms kvs-oparms cn_maint_disable=true
done

# Let compaction run, which should spill all keys into level 1, then verify
# no kvsets in level 0
# shellcheck disable=SC2086
cmd putbin -n 1000 "$home" "$kvs" kvs-oparms cn_close_wait=true $kvdb_oparms
cmd cn_metrics "$home" "$kvs" | cmd -e grep -P "^k${sp}+0,0,0${sp}"

# Validate keys found in level 1, w/ maint disabled.
# shellcheck disable=SC2086
cmd putbin -V "-c$keys" "$home" "$kvs" $kvdb_oparms kvs-oparms cn_maint_disable=true

# Add tombstones, with maint disabled. Verify that one kvset is in root node.
# shellcheck disable=SC2086
cmd putbin -D "-c$keys" "$home" "$kvs" $kvdb_oparms kvs-oparms cn_maint_disable=true
cmd cn_metrics "$home" "$kvs" | cmd grep -P "^n${sp}+0,0,1${sp}"

# Validate keys, w/ maint disabled. Expect error since tombstones block.
# shellcheck disable=SC2086
cmd -e putbin -V -c1 "$home" "$kvs" $kvdb_oparms kvs-oparms cn_maint_disable=true
