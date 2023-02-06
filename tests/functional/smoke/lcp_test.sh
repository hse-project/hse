#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

# Check cursor behaviour with corner cases.
# Note that this test depends on the
# way putbin creates its keys. Any change to that will affect the results of
# this test.

. common.subr

trap cleanup EXIT
kvdb_create

kvs=$(kvs_create smoke-0)

nkeys=1000

# load w/ little endian fmt keys
cmd putbin "$home" "$kvs" "-c$nkeys" -e kvs-oparms cn_maint_disable=true

# create a cursor using the last key in pg 0 of the wbtree as a prefix
key=0x7f010000
cnt=$(awk '{print($1);exit(0)}' <<<"$(cmd pscan "$home" "$kvs" "-p$key" -c kvs-oparms cn_maint_disable=true)")
[[ "$cnt" == "1" ]] ||
    err "Forward cursor didn't find key '$key'"

cnt=$(awk '{print($1);exit(0)}' <<<"$(cmd pscan "$home" "$kvs" "-p$key" -c -r kvs-oparms cn_maint_disable=true)")
[[ "$cnt" == "1" ]] ||
    err "Reverse cursor didn't find key '$key'"
