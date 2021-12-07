#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

output=$(cmd hse kvs drop -h)

echo "$output" | cmd grep --quiet -F "Usage: hse kvs drop [options] <kvdb_home> <kvs>"
echo "$output" | cmd grep --quiet -F "Options:"
