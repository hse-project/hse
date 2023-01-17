#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

#doc: simple transaction test on a KVDB kvs

. common.subr

trap cleanup EXIT
kvdb_create

kvs=$(kvs_create smoke-0)

cmd kmt "$home" "$kvs" -b -i128m -l16 -s1 -t10 -j64
cmd hse kvdb compact -f -t 1200 $home

cn_metrics "$home" "$kvs" | grep -q -P "^t\s+1\s+1\b"
[[ $? == 0 ]] || err "Tree is not fully compacted"

