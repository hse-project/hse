#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: kmt/kvdb insert test: 1 billion 20-byte keys with 50-byte values

. common.subr

trap cleanup EXIT
kvdb_create

kvs=$(kvs_create smoke-0)

threads=$(( 2 * $(nproc) ))
keys=1g

cmd kmt "-j$threads" "-i$keys" -s1 -l50 -b "$home" "$kvs"
cmd cn_metrics "$home" "$kvs"
