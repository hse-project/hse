#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.

. common.subr

trap cleanup EXIT
kvdb_create

kvs=$(kvs_create smoke-0 prefix.length=8)

typeset -i p=100
typeset -i c=50
typeset -i s=10
typeset -i threads=$(($(nproc) / 4 + 1))
typeset -i ramgb

ramgb=$(awk '/^MemAvail/ {printf "%lu", $2 / 1048576}' /proc/meminfo)
if ((ramgb > 16)) ; then
    p=$((p * 10))
    c=$((c * 10))
fi

oparms=(
    kvdb-oparms
    csched_samp_max=100)

# Use probe
cmd pfx_probe "$home" "$kvs" "-p$p" "-c$c" "-s$s" "-j$threads" "${oparms[@]}"

# Use cursors; skip load
cmd pfx_probe "$home" "$kvs" "-p$p" "-c$c" "-s$s" "-j$threads" -v -x -d15 "${oparms[@]}"

# Use gets; skip load
cmd pfx_probe "$home" "$kvs" "-p$p" "-c$c" "-s$s" "-j$threads" -v -g -d15 "${oparms[@]}"
