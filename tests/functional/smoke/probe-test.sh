#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. "$(dirname "${BASH_SOURCE[0]}")/smoke.subr"

trap kvdb_drop EXIT
kvdb_create

# add a KVS to the KVDB
# fanout=16 for a smaller pivot level
kvs=$(kvs_create smoke-0 fanout=16 prefix.length=8 suffix.length=8) || exit $?

typeset -i p=1000
typeset -i c=100
typeset -i s=10
typeset -i threads=$(($(nproc) + 1))
typeset -i ramgb

ramgb=$(awk '/^MemAvail/ {printf "%lu", $2 / 1048576}' /proc/meminfo)
if ((ramgb > 16)) ; then
    p=$((p * 10))
    c=$((c * 10))
fi

oparms=(
    kvdb-oparms
    csched_samp_max=100
    kvs-oparms
    cn_node_size_hi=128
    cn_node_size_lo=128)

# Use probe
cmd pfx_probe "$home" "$kvs" "-p$p" "-c$c" "-s$s" "-j$threads" "${oparms[@]}"

# Use cursors; skip load
cmd pfx_probe "$home" "$kvs" "-p$p" "-c$c" "-s$s" "-j$threads" -v -x -d15 "${oparms[@]}"

# Use gets; skip load
cmd pfx_probe "$home" "$kvs" "-p$p" "-c$c" "-s$s" "-j$threads" -v -g -d15 "${oparms[@]}"
