#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: simple putgetdel test

. common.subr

trap cleanup EXIT
kvdb_create

keys=10000
kvs=$(kvs_create smoke-0)

cmd putgetdel "$home" "$kvs" -c "$keys"
