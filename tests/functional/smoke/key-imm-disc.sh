#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

#doc: test edges of key_immediate and key_disc

. common.subr

trap cleanup EXIT
kvdb_create

key_formats=(
    '%lx'    # 1 byte keys
    '%09lx'  # 9 byte keys
    '%09lx'  # 17 byte keys
    '%022lx' # 22 byte keys (max key_immediate data size)
    '%023lx' # 23 byte keys (max key_immediate data size + 1)
    '%024lx' # 24 byte keys (max key_disc data size)
    '%025lx' # 25 byte keys (max key_disc data size + 1)
)

counter=0

for fmt in "${key_formats[@]}"; do
    kvs=$(kvs_create "smoke-$counter")
    counter=$((counter+1))
    cmd kmt -s1 -c -f "$fmt" -j3 -i16 -t30 "$home" "$kvs"
    cmd kmt -s1 -c -f "$fmt" "$home" "$kvs"
done
