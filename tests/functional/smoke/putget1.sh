#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: simple putgetdel test

. "$(dirname "${BASH_SOURCE[0]}")/smoke.subr"

trap kvdb_drop EXIT
kvdb_create

keys=10000
kvs=$(kvs_create smoke-0) || exit $?

cmd putgetdel "$home" "$kvs" -c "$keys"
