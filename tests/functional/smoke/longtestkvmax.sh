#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: quick longtest focused on key/val max

. common.subr

trap cleanup EXIT
kvdb_create

kvs=$(kvs_create smoke-0)

threads=4
keys=100
seed=$RANDOM

# This test requires '--once' to ensure each thread of each invocation of
# longtest runs through exactly one iteration.
for (( phase = 0; phase <= 9; phase++ )); do
    cmd longtest "$home" "$kvs" -t "$threads" -i 3 --once -c "$keys" --seed "$seed" --mphase $((1<<phase)) --verify 100 --klen 1344 --once -v
    cmd longtest "$home" "$kvs" -t "$threads" -i 3 --once -c "$keys" --seed "$seed" --mphase $((1<<phase)) --verify 100 --vlen 1048576 --once -v
    cmd cn_metrics "$home" "$kvs"
done
