#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

#doc: use putbin to spill and test get

. common.subr

trap kvdb_drop EXIT
kvdb_create

# add 3 KVSes to the KVDB
kvs0=$(kvs_create smoke-0)
kvs1=$(kvs_create smoke-1 prefix.length=2)
kvs2=$(kvs_create smoke-2 prefix.length=3)

keys=70000

rparams="kvdb-oparms log_squelch_ns=0"

# usage: scanfor nkeys $log "$home" $kvs $opts
scanfor() {
    local nk=$1; shift
    shift
    local kv=$1; shift
    local o="$*"; shift

    local n
    n=$(awk '(NR == 2) {print $1}' <<<"$(cmd pscan -c "$home" "$kv" "$rparams" "$o")")

    if [[ "$n" != "$nk" ]]; then
        err "scan $kv $o found $n keys, expected $nk"
    fi
}

for kvs in $kvs0 $kvs1 $kvs2; do
    # ingest
    cmd putbin -c "$keys" "$home" "$kvs" "$rparams"

    # force spill
    cmd putbin -n 1000 "$home" "$kvs" kvdb-oparms csched_debug_mask=0xffffffff cn_close_wait=true csched_rspill_params=0x01ff "$rparams"

    # verify spill occurred
    cmd cn_metrics "$home" "$kvs" | cmd -e grep -P '^n\s+0\s+0\s+'

    # look for keys
    cmd putbin -V -c "$keys" "$home" "$kvs" "$rparams"
    scanfor "$keys" "$home" "$kvs" ""
    scanfor 256   "$home" "$kvs" -p0x000001
    scanfor 256   "$home" "$kvs" -p0x000002
    scanfor 256   "$home" "$kvs" -p0x000003

    # seek for a key too small for scan
    scanfor 256   "$home" "$kvs" -p0x000001 -s0x00000000
    # "typical" seeks
    scanfor 256   "$home" "$kvs" -p0x000001 -s0x00000100
    scanfor 255   "$home" "$kvs" -p0x000001 -s0x00000101
    scanfor 128   "$home" "$kvs" -p0x000001 -s0x00000180
    scanfor 64    "$home" "$kvs" -p0x000002 -s0x000002c0
    # this should be the last key in a page:
    scanfor 52    "$home" "$kvs" -p0x000002 -s0x000002cc
    # and the first key of a page in the middle:
    scanfor 51    "$home" "$kvs" -p0x000002 -s0x000002cd
    scanfor 1     "$home" "$kvs" -p0x000002 -s0x000002ff
    scanfor 0     "$home" "$kvs" -p0x000002 -s0x00000300
    # and too large of a key
    scanfor 0     "$home" "$kvs" -p0x000002 -s0xffffffff
done
