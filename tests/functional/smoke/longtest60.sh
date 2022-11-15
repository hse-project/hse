#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

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
