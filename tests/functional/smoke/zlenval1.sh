#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

#doc: use putgetdel to test zero-length values

. common.subr

trap cleanup EXIT
kvdb_create

keys=100
kvs=$(kvs_create smoke-0)

# Six step test:
# - Put keys with 0-byte values
# - Verify those keys can be found and have vlen==0
# - Update same keys with 10-byte values
# - Verify
# - Update same keys with 0-byte values
# - Verify
cmd putgetdel "$home" "$kvs" -c "$keys" --vlen 0   --put
cmd putgetdel "$home" "$kvs" -c "$keys" --vlen 0  --vput
cmd putgetdel "$home" "$kvs" -c "$keys" --vlen 10  --put
cmd putgetdel "$home" "$kvs" -c "$keys" --vlen 10 --vput
cmd putgetdel "$home" "$kvs" -c "$keys" --vlen 0   --put
cmd putgetdel "$home" "$kvs" -c "$keys" --vlen 0  --vput
