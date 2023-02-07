#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

# Run this on root of source
SRC_ROOT=$(realpath "${1:-"./"}")

# Print the usage of offensive language
bad_words=$(curl -s "https://www.cs.cmu.edu/~biglou/resources/bad-words.txt")
bad_words=$(grep -v -f "${SRC_ROOT}/scripts/dev/checkoss-ignore-words.txt" <<< "${bad_words[*]}")
files=$(git -C "${SRC_ROOT}" ls-files | grep -vE '(doxy|images)')
pushd "${SRC_ROOT}" > /dev/null || exit
# shellcheck disable=SC2086
check_bad_words=$(echo "${files}" | xargs egrep -Hinw "$(echo ${bad_words} | tr ' ' '|')")
popd > /dev/null || exit

exit_code=0
if [ -n "${check_bad_words}" ]; then
    echo -e "Found the following potentially offensive language:\n${check_bad_words}"
    exit_code=$((exit_code + 1))
fi
exit "$exit_code"
