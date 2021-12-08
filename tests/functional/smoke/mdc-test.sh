#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#tdoc: mdc data integrity and perf tests

. "$(dirname "${BASH_SOURCE[0]}")/smoke.subr"

storage="$home/capacity/smoke-mdc-test"

cmd rm -fr "$storage"
cmd mkdir -p "$storage"

cmd mdctest "$storage"

cmd mdcperf -r 64   -c $((  32 * 1024 * 1024)) -v    "$storage"
cmd mdcperf -r 64   -c $((   8 * 1024 * 1024)) -v -s "$storage"
cmd mdcperf -r 4096 -c $((1024 * 1024 * 1024)) -v    "$storage"
cmd mdcperf -r 4096 -c $(( 256 * 1024 * 1024)) -v -s "$storage"

cmd rm -fr "$storage"
