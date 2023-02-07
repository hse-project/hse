#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

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
