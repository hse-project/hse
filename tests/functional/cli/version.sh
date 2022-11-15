#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

. common.subr

trap cleanup EXIT

long_output=$(cmd hse --version)
short_ouptut=$(cmd hse -V)
verbose_output=$(cmd hse -vV)

cmd test "$long_output" == "$short_ouptut"

echo "$short_ouptut" | cmd grep -P "r?[a-zA-Z0-9.]+"

cmd test "$(printf "%s\n" "$verbose_output" | wc -l)" -eq 2
echo "$verbose_output" | cmd grep -P "^version: r?[a-zA-Z0-9.]+"
echo "$verbose_output" | cmd grep -P "^build-configuration: "
