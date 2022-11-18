#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

. common.subr

trap cleanup EXIT

output=$(cmd -e hse kvs create 2>&1)

cmd test "$output" == "$(cmd hse kvs create -h)"
