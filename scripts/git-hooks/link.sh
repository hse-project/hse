#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

set -e

git_hooks_dir="$(git rev-parse --git-path hooks)"

rel_path=$(python3 -c "import os; print(os.path.relpath('$(dirname "${BASH_SOURCE[0]}")', '$git_hooks_dir'))")

# TODO: Add pre-commit hook back when formatting is all sorted out
# shellcheck disable=2043
for hook in post-checkout; do
    if [ ! -f "$git_hooks_dir/$hook" ]; then
        ln -s "$rel_path/$hook" "$git_hooks_dir/$hook"
    else
        echo "Skipping $hook hook because it already exists"
    fi
done
