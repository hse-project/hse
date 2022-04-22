#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

#doc: quick longtest focused on c0

. common.subr

trap kvdb_drop EXIT
kvdb_create

kvs=$(kvs_create smoke-0)

threads=1
keys=5000

cmd longtest "$home" "$kvs" -t "$threads" -i 3 -c "$keys"
cmd cn_metrics "$home" "$kvs"
