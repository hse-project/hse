#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

. common.subr

trap cleanup EXIT

output=$(cmd hse utils strerror -h)

echo "$output" | cmd grep -F "Usage: hse utils strerror [options] [--] <errorcode>"
echo "$output" | cmd grep -F "Options:"
