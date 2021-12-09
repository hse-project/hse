#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: quick longtest focused on cn

. "$(dirname "${BASH_SOURCE[0]}")/smoke.subr"

trap kvdb_drop EXIT
kvdb_create

# add 3 KVSes to the KVDB
kvs=$(kvs_create smoke-1) || exit $?

threads=4
keys=100000
seed=$RANDOM

# This test requires '--once' to ensure each thread of each invocation of
# longtest runs through exactly one iteration.
for (( phase = 0; phase <= 9; phase++ )); do
    cmd longtest "$home" "$kvs" -t "$threads" -c "$keys" --mphase $((1<<phase)) --verify 100 --seed "$seed" --once -v
    cmd cn_metrics "$home" "$kvs"
done
