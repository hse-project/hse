#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#tdoc: quick mpool IO test using kmt (50%, 20% and 5% writes)

. common.subr

trap cleanup EXIT
kvdb_create

seconds=30

cmd kmt -i128 "-t$seconds" -bcDR -s1 -w50 -osecsz=4k "-j$(nproc)" "mpool:$home/capacity"
cmd kmt -i128 "-t$seconds" -bcDR -s1 -w20 -osecsz=1m "-j$(nproc)" "mpool:$home/capacity"
cmd kmt -i128 "-t$seconds" -bcDR -s1 -w5 -osecsz=32m "-j$(nproc)" "mpool:$home/capacity"
