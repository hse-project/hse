#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

#doc: quick kvdb/cn performance test using kmt (60s, 5% writes)

. common.subr

trap cleanup EXIT
kvdb_create

w=5
seconds=60

kvs=$(kvs_create smoke-0)

cmd kmt -i20m "-t$seconds" -bcDR -s1 "-w$w" "-j$(nproc)" "$home" "$kvs"
