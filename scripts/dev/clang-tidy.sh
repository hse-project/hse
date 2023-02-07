#!/bin/sh

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2022 Micron Technology, Inc. All rights reserved.

if ! type clang-tidy > /dev/null 2>&1; then
    >&2 echo "clang-tidy not found"
    exit 1
fi

if [ -z "$MESON_BUILD_ROOT" ]; then
    >&2 echo "Not running in a Meson context, use \"ninja -C \$builddir clang-tidy\""
    exit 1
fi

source_root=$(realpath "$(dirname "$(dirname "$(dirname "$0")")")")

find "$source_root/cli" "$source_root/include" \
    "$source_root/lib/config" "$source_root/lib/error" \
    "$source_root/lib/logging" "$source_root/lib/pidfile" \
    "$source_root/lib/rest" "$source_root/samples" \
    -name "*.[ch]" -type f -print0 \
    | xargs -r --null \
        clang-tidy -p "$MESON_BUILD_ROOT" --warnings-as-errors \
            --config-file="$source_root/.clang-tidy" --format-style=none
