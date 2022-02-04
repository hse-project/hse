#!/bin/sh

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

if ! type clang-format > /dev/null 2>&1; then
    >&2 echo "clang-format not found"
    exit 1
fi

if ! type black > /dev/null 2>&1; then
    >&2 echo "black not found"
    exit 1
fi

usage () {
    printf "%s\n\n" "Usage: format [OPTIONS]"
    printf "\t%s\n\n" "Formatting script for HSE source code and files"
    printf "%s\n" "Options:"
    printf "\t%s\n" "-h\tPrint help"
    printf "\t%s\n" "-c\tCheck if files are formatted properly"
}

# Path to source root. MESON_SOURCE_ROOT is set during script runs, but this
# script won't always be run through Meson.
source_root=$(realpath "$(dirname "$(dirname" $(dirname "$0")")")")

files=$(find \
    "${source_root}/cli" \
    "${source_root}/hsejni" \
    "${source_root}/include" \
    "${source_root}/lib" \
    "${source_root}/samples" \
    "${source_root}/tests" \
    "${source_root}/tools" \
    -type f \( -name "*.[ch]" -o -name "*.h.in" \) -print)

clang_format_help=$(clang-format --help)
echo "$clang_format_help" | grep -- "--Werror"
clang_format_has_werror=$?
echo "$clang_format_help" | grep -- "--dry-run"
clang_format_has_dry_run=$?

check=0
while getopts "hc" arg; do
    case "${arg}" in
        h)
            usage
            exit 0
            ;;
        c)
            check=1
            ;;
        ?)
            >&2 echo "Invalid option '${arg}'"
            usage
            exit 1
            ;;
        *) exit 2;;
    esac
done

if [ "$check" -eq 1 ]; then
    found_issues=0

    if [ "$clang_format_has_dry_run" -eq 0 ] && [ "$clang_format_has_werror" -eq 0 ]; then
        if ! clang-format --style=file --dry-run --Werror "$files"; then
            found_issues=1
        fi
    else
        if ! clang-format --style=file -i "$files" && git diff-files --quiet; then
            found_issues=1
        fi
    fi

    if ! black --check --diff "$source_root"; then
        found_issues=1
    fi

    if [ "$found_issues" -ne 0 ]; then
        exit 2
    fi
else
    clang-format --style=file -i "$files"
    black "$source_root"
fi
