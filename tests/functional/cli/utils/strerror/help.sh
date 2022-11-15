#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

. common.subr

trap cleanup EXIT

output=$(cmd hse utils strerror -h)

echo "$output" | cmd grep -F "Usage: hse utils strerror [options] [--] <errorcode>"
echo "$output" | cmd grep -F "Options:"
