#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: quick longtest focused on c0

. common.subr

trap cleanup EXIT
kvdb_create

kvs=$(kvs_create smoke-0)

threads=1
keys=5000

cmd longtest "$home" "$kvs" -t "$threads" -i 3 -c "$keys"
cmd cn_metrics "$home" "$kvs"
