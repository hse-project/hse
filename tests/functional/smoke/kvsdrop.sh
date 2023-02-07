#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: test to verify kvs drop functionality, specifically testing the edge condition where the last transactions are completely removed.

. common.subr

trap cleanup EXIT
kvdb_create

keys=10

kvs1=$(kvs_create smoke-0)
kvs2=$(kvs_create smoke-1)

cmd hse kvdb info "$home" | cmd grep "$kvs1"
cmd hse kvdb info "$home" | cmd grep "$kvs2"

# load kvs1 and kvs2
cmd putbin "-c$keys" "$home" "$kvs1"
cmd putbin "-c$keys" "$home" "$kvs2"

# verify kvs1
cmd putbin -V "-c$keys" "$home" "$kvs1"
cmd hse kvdb info "$home" | cmd grep "$kvs1"

# verify kvs2
cmd putbin -V "-c$keys" "$home" "$kvs2"
cmd hse kvdb info "$home" | cmd grep "$kvs2"

# drop kvs2
kvs_drop "$kvs2"

# verify kvs1
cmd putbin -V "-c$keys" "$home" "$kvs1"
cmd hse kvdb info "$home" | cmd grep "$kvs1"

# Verify kvs2 does not exist
cmd hse kvdb info "$home" | cmd -e grep "$kvs2"
