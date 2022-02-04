#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

trap kvdb_drop EXIT

kvdb_create

output=$(cmd hse storage profile --quiet "$home")

echo "$output" | cmd grep -P "(medium|heavy|light)"

output=$(cmd hse storage profile "$home")

echo "$output" | cmd grep -P "Recommended throttling\.init_policy: \"(medium|heavy|light)\""
