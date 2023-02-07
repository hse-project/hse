#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: quick kvdb/cn performance test using kmt (60s, 50% writes)

. common.subr

trap cleanup EXIT
kvdb_create

w=50
seconds=60

kvs=$(kvs_create smoke-0)

cmd kmt -i20m "-t$seconds" -bcDR -s1 "-w$w" "-j$(nproc)" "$home" "$kvs"
