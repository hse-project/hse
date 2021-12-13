#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

output=$(cmd hse utils -h)

echo "$output" | cmd grep --quiet -F "Usage: hse utils [options] <command> ..."
echo "$output" | cmd grep --quiet -F "Options:"
echo "$output" | cmd grep --quiet -F "Commands:"
echo "$output" | cmd grep --quiet -F "strerror"
