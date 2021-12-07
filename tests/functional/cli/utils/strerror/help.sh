#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

output=$(cmd hse utils strerror -h)

echo "$output" | cmd grep --quiet -F "Usage: hse utils strerror [options] [--] <errorcode>"
echo "$output" | cmd grep --quiet -F "Options:"
