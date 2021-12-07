#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: quick kvdb/c0 read performance test using kmt (60s)

. common.subr

trap kvdb_drop EXIT
kvdb_create

seconds=60

kvs=$(kvs_create smoke-0) || $?
cmd kmt -i1000 "-t$seconds" -bcDOR -w0 "-j$(nproc)" -s1 "$home" "$kvs"
