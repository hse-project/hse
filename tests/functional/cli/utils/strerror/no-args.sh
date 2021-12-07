#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

output=$(cmd -e hse utils strerror 2>&1)

cmd test "$output" == "$(hse utils strerror -h)"
