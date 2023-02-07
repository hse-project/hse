#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

. common.subr

trap cleanup EXIT

output=$(cmd hse kvs create -h)

echo "$output" | cmd grep -F "Usage: hse kvs create [options] <kvdb_home> <kvs> [<param>=<value>]..."
echo "$output" | cmd grep -F "Options:"
echo "$output" | cmd grep -F "Parameters:"
