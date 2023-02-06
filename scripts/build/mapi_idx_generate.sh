#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

set -u
set -e
set -o pipefail

mkdir -p "${3}"

target=${1}
project_root=${2}
inputs=${4}
file="${3}/inputs"

sed "s/\ /\x00/g" <<<"$inputs" | tr -d '\n' > "$file"

xargs -0 -n1 "$project_root/scripts/build/utpp" -- -m < "$file" \
    | sort -u \
    | awk > "$target" '
    BEGIN {
        print "/* GENERATED FILE: DO NOT EDIT */"
        print "#ifndef GEN_MAPI_IDX_H"
        print "#define GEN_MAPI_IDX_H"
        print "enum mapi_idx {"
    }
    {
        print "\tmapi_idx_" $1 " = " cnt++ ","
    }
    END {
        # intentionally anti-pattern, so does not hide any names
        print "\tmax_mapi_idx = " cnt "\n};"
        print "#endif"
    }'

exit 0
