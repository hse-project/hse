#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

. common.subr

trap cleanup EXIT
kvdb_create

output=$(cmd -i hse storage profile --quiet "$home")
status=$?
if [ "$status" -ne 0 ]; then
    if echo "$output" | grep --quiet -P "The profiling test needs \d+ MiB of free space to characterize KVDB performance."; then
        # Skip the test since we don't have enough space to run it.
        exit "$SKIP_STATUS"
    else
        exit "$status"
    fi
fi

echo "$output" | cmd grep -P "(medium|heavy|light)"

output=$(cmd hse storage profile "$home")

echo "$output" | cmd grep -P "Recommended throttling\.init_policy: \"(medium|heavy|light)\""
