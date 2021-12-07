#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

output=$(cmd hse kvdb compact -h)

echo "$output" | cmd grep --quiet -F "Usage: hse kvdb compact [options] <kvdb_home>"
echo "$output" | cmd grep --quiet -F "Options:"
