#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: simple putgetdel test on a KVDB kvs

. common.subr

trap cleanup EXIT
kvdb_create

keys=10000
t=4   #threads

# add 4 KVSes to the KVDB
kvs1=$(kvs_create smoke-0)
kvs2=$(kvs_create smoke-1)
kvs3=$(kvs_create smoke-2)
kvs4=$(kvs_create smoke-3)

kvs_list="$kvs1,$kvs2,$kvs3,$kvs4"

cmd putgetdel "$home" "$kvs_list" -v -t "$t" -c "$keys"
cmd putgetdel "$home" "$kvs_list" -v -t "$t" -c "$keys" --sync
cmd putgetdel "$home" "$kvs_list" -v -t "$t" -c "$keys" --ckvs
cmd putgetdel "$home" "$kvs_list" -v -t "$t" -c "$keys" --ckvdb
