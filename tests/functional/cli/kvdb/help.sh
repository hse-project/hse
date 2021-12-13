#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

output=$(cmd hse kvdb -h)

echo "$output" | cmd grep --quiet -F "Usage: hse kvdb [options] <command> ..."
echo "$output" | cmd grep --quiet -F "Options:"
echo "$output" | cmd grep --quiet -F "Commands:"
echo "$output" | cmd grep --quiet -F "create"
echo "$output" | cmd grep --quiet -F "drop"
echo "$output" | cmd grep --quiet -F "info"
echo "$output" | cmd grep --quiet -F "compact"
