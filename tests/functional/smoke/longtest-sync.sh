#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: 60s longtest with sync without cursors

. common.subr

trap cleanup EXIT
kvdb_create

kvs=$(kvs_create smoke-0)

keys=$((1*1000*1000))
threads=4
seconds=60

# use skewed distribution, and tell last thread (with fewest keys) to sync once per iteration.
args=()
args+=(-t "$threads" -s "$seconds" -c "$keys" -v)
args+=(--poly=4) # skewed distribution
args+=(--sync=$((threads-1)))
args+=(--verify=100)
args+=(kvs-oparms cn_compaction_debug=3)

cmd longtest "$home" "$kvs" "${args[@]}"
cmd cn_metrics "$home" "$kvs"
