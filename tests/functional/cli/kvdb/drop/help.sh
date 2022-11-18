#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

. common.subr

trap cleanup EXIT

output=$(cmd hse kvdb drop -h)

echo "$output" | cmd grep -F "Usage: hse kvdb drop [options] <kvdb_home>"
echo "$output" | cmd grep -F "Options:"
