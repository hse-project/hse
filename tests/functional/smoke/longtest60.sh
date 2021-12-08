#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: 60s longtest

. "$(dirname "${BASH_SOURCE[0]}")/smoke.subr"

trap kvdb_drop EXIT
kvdb_create

kvs=$(kvs_create smoke-0) || exit $?

keys=$((20*1000*1000))
threads=$(nproc)
seconds=60

cmd longtest "$home" "$kvs" -t "$threads" -s "$seconds" -c "$keys"
cmd cn_metrics "$home" "$kvs"
