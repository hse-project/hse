#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

#doc: test ptree semantics

. common.subr

trap kvdb_drop EXIT
kvdb_create

kvs=$(kvs_create smoke-0 prefix.length=8)

# Test 1: Should result in 2 kblocks
keys=1300000
ptombs=300000

rparams='kvs-oparms cn_maint_disable=true'

cmd ptree-overload "$home" "$kvs" -k "$keys" -p "$ptombs" "${rparams}"
cmd cn_metrics "$home" "$kvs"
nkvset=$(cmd cn_metrics "$home" "$kvs" | grep -c ^k)
[[ $nkvset == 1 ]] || err "Expected only one kvset. Found $nkvset kvsets"

nkblks=$(cn_metrics "$home" "$kvs" | awk '$1 ~ /^k/ {print $14}')
[[ $nkblks == 2 ]] || err "Expected two kblocks. Found $nkblks kblocks"

# Test 2: Should result in 1 kblock
kvs=$(kvs_create prefix.length=8) || err
keys=1000000
ptombs=300000

cmd ptree-overload "$home" "$kvs" -k "$keys" -p "$ptombs" "${rparams}"
cmd cn_metrics "$home" "$kvs"
nkvset=$(cmd cn_metrics "$home" "$kvs" | grep -c ^k)
[[ $nkvset == 1 ]] || err "Expected only one kvset. Found $nkvset kvsets"

nkblks=$(cmd cn_metrics "$home" "$kvs" | awk '$1 ~ /^k/ {print $14}')
[[ $nkblks == 1 ]] || err "Expected one kblock. Found $nkblks kblocks"
