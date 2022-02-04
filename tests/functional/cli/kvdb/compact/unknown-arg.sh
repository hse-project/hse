#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

output=$(cmd -e hse kvdb compact --does-not-exist 2>&1)

echo "$output" | cmd grep -F "hse kvdb compact: invalid option '--does-not-exist', use -h for help"
