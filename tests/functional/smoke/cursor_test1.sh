#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

trap kvdb_drop EXIT
kvdb_create

# add a KVS to the KVDB
kvs=$(kvs_create smoke-0) || exit $?

# 1. Create 10000 cursors spread across 20 threads - each thread gets a few
#    cursors
# 2. Load all keys - each thread loads its share of keys
# 3. Each thread updates its cursors and each of these cursors verify a part of
#    the thread's key space

keys=$((1000 * 1000 * 4))
nthread=20
ncursor=10000
cmd multicursor "$home" "$kvs" "-c$keys" "-j$nthread" "-r$ncursor" -l -v kvs-oparms cn_node_size_lo=32 cn_node_size_hi=32

#
# capput tests
#
chunksz=1000
wth=96
rth=2
batchsz=500000
pwin=100
dur=30

# regular kvs
kvs=$(kvs_create smoke-1 prefix.length=8)
cmd capput "$home" "$kvs" "-j$wth" "-t$rth" "-c$chunksz" "-b$batchsz" "-m$pwin" "-d$dur" -v kvs-oparms cn_node_size_lo=32 cn_node_size_hi=32

# capped kvs
kvs=$(kvs_create smoke-2 prefix.length=8 kvs_ext01=1)
cmd capput "$home" "$kvs" "-j$wth" "-t$rth" "-c$chunksz" "-b$batchsz" "-m$pwin" "-d$dur" -v
