#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

. common.subr

trap cleanup EXIT

output=$(cmd -e hse storage profile 2>&1)

cmd test "$output" == "$(hse storage profile -h)"
