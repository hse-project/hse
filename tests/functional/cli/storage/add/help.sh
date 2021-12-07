#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

output=$(cmd hse storage add -h)

echo "$output" | cmd grep --quiet -F "Usage: hse storage add [options] <kvdb_home> [<param>=<value>]..."
echo "$output" | cmd grep --quiet -F "Options:"
