#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.

#doc: simple kmt test on KVDB

. common.subr

trap kvdb_drop EXIT
kvdb_create

jobs=$(($(nproc) / 4 + 3))
recmax=$((128 * jobs))

kvs1=$(kvs_create smoke-0) || $?
kvs2=$(kvs_create smoke-1) || $?
kvs3=$(kvs_create smoke-2) || $?
kvs4=$(kvs_create smoke-3) || $?

cmd kmt -i "$recmax" -t10 -c -j"$jobs" -w50 "$home" "$kvs1"
cmd kmt -t10 -cD -j"$jobs" -w50 "$home" "$kvs1" kvs-oparms cn_verify=true

# test ingest + cn
cmd kmt -i3m -t15 -cD -bl0 -j"$jobs" -w50 "$home" "$kvs2" kvs-oparms cn_verify=true kvdb-oparms c0_debug=1

# hammer on c0 update
cmd kmt -i448 -t15 -cD -j"$jobs" -w50 -b "$home" "$kvs3" kvdb-oparms c0_debug=1

# test LC by sync-ing every 100ms and using txns
cmd kmt -i "$recmax" -s1 -T15 -c -j"$jobs" -w50 -y100 "$home" "$kvs4"
