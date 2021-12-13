#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

output=$(cmd hse kvs create -h)

echo "$output" | cmd grep --quiet -F "Usage: hse kvs create [options] <kvdb_home> <kvs> [<param>=<value>]..."
echo "$output" | cmd grep --quiet -F "Options:"
echo "$output" | cmd grep --quiet -F "Parameters:"
