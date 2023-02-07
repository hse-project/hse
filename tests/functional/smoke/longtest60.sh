#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: 60s longtest

. common.subr

trap cleanup EXIT
kvdb_create

kvs=$(kvs_create smoke-0)

keys=$((20*1000*1000))
threads=$(nproc)
seconds=60

cmd longtest "$home" "$kvs" -t "$threads" -s "$seconds" -c "$keys"
cmd cn_metrics "$home" "$kvs"
