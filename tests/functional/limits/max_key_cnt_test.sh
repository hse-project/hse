#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.

# Test whether 200 billion records can be added to a KVDB

. common.subr

trap kvdb_drop EXIT
kvdb_create

kvs=$(kvs_create large_db)

nkeys=$((200 * 1000 * 1000 * 1000))
nthread=$(nproc)
swaptime=$((20 * 60))

cmd kmt "$home" "$kvs" -b -i"$nkeys" -l0 -s1 -t"$swaptime" -j"$nthread"
