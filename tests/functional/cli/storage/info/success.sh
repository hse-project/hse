#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

trap kvdb_drop EXIT

kvdb_create

output=$(cmd hse storage info "$home")

echo "$output" | cmd grep --quiet -F "MEDIA_CLASS"
echo "$output" | cmd grep --quiet -F "ALLOCATED_BYTES"
echo "$output" | cmd grep --quiet -F "USED_BYTES"
echo "$output" | cmd grep --quiet -F "PATH"

echo "$output" | cmd grep --quiet -F "capacity"
echo "$output" | cmd grep --quiet -F "staging"
echo "$output" | cmd grep --quiet -F "pmem"

echo "$output" | cmd grep --quiet -F "$home/capacity"

cmd test "$(echo "$output" | cmd wc -l)" -eq 4
