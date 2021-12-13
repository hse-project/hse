#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: Query fixed length ranges while updating random records.

. common.subr

trap kvdb_drop EXIT
kvdb_create

kvs=$(kvs_create smoke-0 prefix.length=8) || $?

range_read_logs="$home/range_read_logs"

# Load
nthread=128
vlen=1024
npfx=8
nsfx=200000 # (npfx * nsfx) keys total
cmd range_read "$home" "$kvs" -f "$range_read_logs" -l "-j$nthread" "-v$vlen" "-p$npfx" "-s$nsfx" kvs-oparms cn_node_size_lo=32 cn_node_size_hi=32

cmd kvck "$home"

# Query
nthread=32
duration=20 # seconds
range=10
cmd range_read "$home" "$kvs" -f "$range_read_logs" -e "-b$range" "-j$nthread" "-v$vlen" "-p$npfx" "-s$nsfx" "-d$duration" -V
cmd range_read "$home" "$kvs" -f "$range_read_logs" -e "-b$range" "-j$nthread" "-v$vlen" "-p$npfx" "-s$nsfx" "-d$duration" -V
