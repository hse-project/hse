#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

output=$(cmd hse storage profile -h)

echo "$output" | cmd grep -F "Usage: hse storage profile [options] <storage_path>"
echo "$output" | cmd grep -F "Options:"
