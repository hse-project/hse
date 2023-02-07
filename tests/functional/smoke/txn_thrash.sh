#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

. common.subr

trap cleanup EXIT
kvdb_create

kvs=$(kvs_create smoke-0)

# Single threaded large transaction
cmd txn_thrash "$home" "$kvs" -j1 -c500000

# Multi threaded, relatively small txns
cmd txn_thrash "$home" "$kvs" -j16 -c200000
