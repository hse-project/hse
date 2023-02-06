#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

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
