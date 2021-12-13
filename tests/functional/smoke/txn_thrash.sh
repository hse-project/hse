#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

trap kvdb_drop EXIT
kvdb_create

kvs=$(kvs_create smoke-0) || exit $?

# Single threaded large transaction
cmd txn_thrash "$home" "$kvs" -j1 -c500000

# Multi threaded, relatively small txns
cmd txn_thrash "$home" "$kvs" -j16 -c200000
