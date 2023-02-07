#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

. common.subr

trap cleanup EXIT

output=$(cmd hse kvdb create -h)

echo "$output" | cmd grep -F "Usage: hse kvdb create [options] <kvdb_home> [<param>=<value>]..."
echo "$output" | cmd grep -F "Options:"
