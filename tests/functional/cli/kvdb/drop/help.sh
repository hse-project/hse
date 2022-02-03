#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

output=$(cmd hse kvdb drop -h)

echo "$output" | cmd grep -F "Usage: hse kvdb drop [options] <kvdb_home>"
echo "$output" | cmd grep -F "Options:"
