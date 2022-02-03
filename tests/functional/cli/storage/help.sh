#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

output=$(cmd hse storage -h)

echo "$output" | cmd grep -F "Usage: hse storage [options] <command> ..."
echo "$output" | cmd grep -F "Options:"
echo "$output" | cmd grep -F "Commands:"
echo "$output" | cmd grep -F "add"
echo "$output" | cmd grep -F "info"
echo "$output" | cmd grep -F "profile"
