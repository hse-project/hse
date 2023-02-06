#!/bin/sh

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.

if ! type clang-tidy > /dev/null 2>&1; then
    >&2 echo "clang-tidy not found"
    exit 1
fi

if [ -z "$MESON_BUILD_ROOT" ]; then
    >&2 echo "Not running in a Meson context, use \"ninja -C \$builddir clang-tidy\""
    exit 1
fi

source_root=$(realpath "$(dirname "$(dirname "$(dirname "$0")")")")

files=$(find "$source_root/include" "$source_root/cli" "$source_root/samples" \
    "$source_root/lib/error" "$source_root/lib/logging" \
    "$source_root/lib/rest" -name "*.[ch]" -type f -print0 | xargs --null)

# shellcheck disable=SC2086 disable=SC2154 # Need word splitting for $files
clang-tidy -p $MESON_BUILD_ROOT --warnings-as-errors \
    --config-file="$source_root/.clang-tidy" --format-style=none $files
