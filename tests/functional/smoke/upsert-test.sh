#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2022 Micron Technology, Inc. All rights reserved.

. common.subr

trap kvdb_drop EXIT
kvdb_create

kvs=$(kvs_create smoke-0)

nth=32
stride=100
nkeys=$((5 * 1000 * 1000))
laps=2

# Use prefix probe
cmd upsert "$home" "$kvs" -j"$nth" -c"$nkeys" -s"$stride" -l"$laps" -m0

# Use point gets
cmd upsert "$home" "$kvs" -j"$nth" -c"$nkeys" -s"$stride" -l"$laps" -m1

# Use cursors
cmd upsert "$home" "$kvs" -j"$nth" -c"$nkeys" -s"$stride" -l"$laps" -m2
