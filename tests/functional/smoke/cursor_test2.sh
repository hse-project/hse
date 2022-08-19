#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.

#doc: Query fixed length ranges while updating random records.

. common.subr

trap kvdb_drop EXIT
kvdb_create

kvs=$(kvs_create smoke-0)

# Load
nthread=$(($(nproc) / 4 + 3))
vlen=1024
nkeys=1600000
cmd range_read "$home" "$kvs" -l "-j$nthread" "-v$vlen" "-n$nkeys"

# Query without warmup
duration=20 # seconds
range=10
cmd range_read "$home" "$kvs" -e "-b$range" "-j$nthread" "-v$vlen" "-n$nkeys" "-d$duration" -V
