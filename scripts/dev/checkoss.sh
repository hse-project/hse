#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

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

# Check for valid license and copyright
src_files=$(git -C "${SRC_ROOT}" ls-files | grep -E '\.(c|h|py|sh|java)$' | grep -v 'subprojects\|simpledrop')
shell_files=$(grep -Er '^#!/.*sh' "${SRC_ROOT}" | sed 's/:.*$//pi' | grep -vE '(subprojects|build.*|.git)')
src_files=$(echo -e "${src_files}\n${shell_files}")
pushd "${SRC_ROOT}" > /dev/null || exit
for file in ${src_files}; do
    if ! head -10 "${file}" | grep -qE "\s*[/#*]*\s*SPDX-License-Identifier:\s+Apache-2.0"; then
        check_license="${check_license}\ninvalid or missing SPDX license identifier: ${file}"
    fi
    if ! head -10 "${file}" | grep -qE "^(.*)\bCopyright\s+\(C\)\s+([0-9]|,|-|\s)*\s+Micron\s+Technology,\s+Inc\.\s*(.*)"; then
        check_license="${check_license}\nCopyright check error: ${file}"
    fi
done
popd > /dev/null || exit

exit_code=0
if [ -n "${check_bad_words}" ]; then
    echo -e "Found the following potentially offensive language:\n${check_bad_words}"
    exit_code=$((exit_code + 1))
fi
if [ -n "${check_license}" ]; then
    echo -e "Check following files for License/Copyright:\n${check_license}"
    exit_code=$((exit_code + 1))
fi
exit "$exit_code"
