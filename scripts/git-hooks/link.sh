#!/bin/sh

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

git_hooks_dir="$(git rev-parse --git-path hooks)"

rel_path=$(realpath --relative-to "$git_hooks_dir" "$(dirname "$(realpath "$0")")")

# TODO: Add pre-commit hook back when formatting is all sorted out
# shellcheck disable=2043
for hook in post-checkout; do
    if [ ! -f "$git_hooks_dir/$hook" ]; then
        ln -s "$rel_path/$hook" "$git_hooks_dir/$hook"
    else
        echo "Skipping $hook hook because it already exists"
    fi
done
