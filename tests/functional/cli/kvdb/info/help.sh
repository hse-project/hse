#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

output=$(cmd hse kvdb info -h)

echo "$output" | cmd grep --quiet -F "Usage: hse kvdb info [options] <kvdb_home>"
echo "$output" | cmd grep --quiet -F "Options:"
