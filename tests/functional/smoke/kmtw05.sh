#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: quick kvdb/cn performance test using kmt (60s, 5% writes)

. common.subr

trap kvdb_drop EXIT
kvdb_create

w=5
seconds=60

kvs=$(kvs_create smoke-0) || exit $?

cmd kmt -i20m "-t$seconds" -bcDR -s1 "-w$w" "-j$(nproc)" "$home" "$kvs"
