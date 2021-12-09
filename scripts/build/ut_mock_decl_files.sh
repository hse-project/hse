#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

# Usage: ut_mock_decl_files.sh <directory 1> <directory 2> ...

usage()
{
    echo "Usage: $CMD <directory 1> <directory 2> ..."
    exit 1
}

CMD=${0##*/}

if [ $# -eq 0 ]; then
    usage
    exit 1
fi

for arg in "$@" ; do
    find "$arg" -name '*.h' -exec sh -c '
        if grep -m 1 MTF_MOCK_DECL $1 > /dev/null 2>&1; then
            echo $1
        fi
    ' sh {} \;
done
