#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: quick kvdb/c0 read performance test using kmt (60s)

. common.subr

trap cleanup EXIT
kvdb_create

seconds=60

kvs=$(kvs_create smoke-0)
cmd kmt -i1000 "-t$seconds" -bcDOR -w0 "-j$(nproc)" -s1 "$home" "$kvs"
