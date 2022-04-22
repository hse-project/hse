#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

#doc: test to verify kvs drop functionality, specifically testing the edge condition where the last transactions are completely removed.

. common.subr

trap kvdb_drop EXIT
kvdb_create

keys=10

kvs=$(kvs_create smoke-0)
kvs2=$(kvs_create smoke-1)

cmd putbin "-c$keys" "$home" "$kvs"
cmd putbin "-c$keys" "$home" "$kvs2"

# validate
cmd putbin -V "-c$keys" "$home" "$kvs"
cmd putbin -V "-c$keys" "$home" "$kvs2"

kvs_drop "$kvs2"

# validate cndb and that cnid 1 keys exist
cmd putbin -V "-c$keys" "$home" "$kvs"

# get tree metrics
# verify that cnid 2 is not present
cmd cndb_log "$home" | cmd -e grep 'cnid 2'
