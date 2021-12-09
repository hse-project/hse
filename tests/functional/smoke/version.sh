#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: test HSE CLI version command

. "$(dirname "${BASH_SOURCE[0]}")/smoke.subr"

output=$(hse -v --version) || exit $?

# Check for three lines of output
count=$(wc -l <<<"$output") || exit $?
if [[ "$count" != 2 ]]; then
    err "Expect two lines of output from command:" \
        "hse --version" \
        "\nFound $count lines"
fi

# Check output fields
fields=$(sort <<<"$(sed -ne 's/:.*//p' <<<"$output")" | xargs)
[[ "$fields" == "build-configuration version" ]] ||
    err "Expect fields: build-configuration and version" \
        "\nFound: $fields"
