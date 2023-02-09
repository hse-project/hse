#!/bin/bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

CMD=${0##*/}

CLANG_FORMAT_VERSION=15
CLANG_FORMAT_REGEX='(1[5-9]|[2-9][0-9])'

set -u

err () {
    prefix="$CMD: "
    while (( $# > 0 )); do
        echo "$prefix$1"
        shift
        prefix=
    done 1>&2
    exit 1
}

syntax () {
    err "$@" "Use -h for help"
}

help () {
    long_help=$1
    cat<<EOF
Usage: $CMD [options] [<path> ...]
$CMD uses clang-format to recursively format and check HSE source code.
Options:
  -c  check if files are formatted properly
  -h  print help
  -H  print more help
  -q  be quiet
  -v  be verbose
EOF

    if (( long_help == 0)); then
       return
    fi

    cat <<EOF

$CMD works recursively on all '*.c', '*.h', and '*.h.in' files under each given
path.  If no path is given, the current working directory is used.

Notes:
- $CMD must be executed from the root of the HSE source tree.
- Files in subprojects are skipped.
- Requires clang-format version $CLANG_FORMAT_VERSION or higher.
- Option '-c' exits with 0 status and no output if and only if there are
  no errors and all checked files are formatted correctly.
EOF
}

check=0
verbose=0
while getopts ":chHv" op; do
    case "$op" in
        (c) check=1;;
        (h) help 0; exit 0;;
        (H) help 1; exit 0;;
        (v) verbose=1;;
        (:) err "Option -$OPTARG requires an argument";;
        (*) err "Invalid option: -$OPTARG";;
    esac
done

# consume parsed command-line arguments
shift $((OPTIND - 1))

if ! type clang-format > /dev/null 2>&1; then
    err "clang-format not found"
fi

# don't need pipefail here bc if clang-format fails, so will grep
if ! clang-format --version 2>&1 | grep -qPi "^clang-format version $CLANG_FORMAT_REGEX"; then
    err "Need clang-format version $CLANG_FORMAT_VERSION or higher"
fi

if [[ ! -f meson_options.txt ]]; then
    err "Running from a directory that doesn't seem to be the top of an HSE source tree"
fi

if (( $# == 0 )); then
    set -- .  # sets path to current directory
fi

for p in "$@"; do
    if [[ -d "$p" ]]; then
        :
    elif [[ -f "$p" ]]; then
        if [[ "$p" =~ .*\.(c|h|h\.in)$ ]]; then
            :
        else
            err "File '$p' is not a C file"
        fi
    else
        err "Path '$p' is neither a directory or a file"
    fi
done

clang_format_extra_flags=()
if (( verbose )); then
    clang_format_extra_flags+=("--verbose")
fi
if (( check )); then
    clang_format_extra_flags+=("--dry-run")
fi

# need pipefail in unexpected case that find errors out
set -o pipefail
find "$@" -name .git -prune -o -name subprojects -prune -o \
    -type f \( -name '*.[ch]' -o -name '*.h.in' \) -print0 \
    | xargs -r0 clang-format "${clang_format_extra_flags[@]}" \
        --Werror -style=file -i -fallback-style=none

exit $?
