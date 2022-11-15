#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

. common.subr

trap cleanup EXIT
kvdb_create

output=$(cmd hse storage info "$home")

echo "$output" | cmd grep -F "MEDIA_CLASS"
echo "$output" | cmd grep -F "ALLOCATED_BYTES"
echo "$output" | cmd grep -F "USED_BYTES"
echo "$output" | cmd grep -F "PATH"

echo "$output" | cmd grep -F "capacity"

echo "$output" | cmd grep -F "$home/capacity"

cmd test "$(echo "$output" | cmd wc -l)" -eq 2
