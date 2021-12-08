#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

# This test creates a small kvs in which all keys start with an "x"
# (the primary prefix) followed by one of 13 secondary prefixes,
# followed by an ID unique to the preceding prefix.
#
# We then test that we can scan and find all keys by both their
# primary and secondary prefixes.

. "$(dirname "${BASH_SOURCE[0]}")/smoke.subr"

trap kvdb_drop EXIT
kvdb_create

kvs=$(kvs_create smoke-0) || exit $?

typeset -i pfxmax=12
typeset -i total=0
typeset -i found
typeset -i i

i=1
while (( i <= pfxmax )) ; do
    pfx=$(printf "x%04d" "$i")
    cmd kmt -j7 -f "${pfx}_%lu" -i $((100 * i)) "$home" "$kvs"
    total+=$((100 * i))
    i=$((i + 1))
done

# The count of keys with unique prefixes should be ${pfxmax}
#
found=$(cmd pscan -c -k6 -u "$home" "$kvs" | awk '$1 !~ /^#/ && $2 ~ /unique/ {print $1}')
if [ "$found" -ne "$pfxmax" ] ; then
    echo "error: invalid unique prefix count, expected $pfxmax, got $found" >&2
    exit 1
fi

sed 1d <<<"$(cmd pscan "$home" "$kvs")" > "$home/pscan.1"

found=$(pscan -c "$home" "$kvs" | awk '{print $1}')
if [ "$found" -ne "$total" ] ; then
    echo "error:  full scan failed to find all $total keys" >&2
    exit 1
fi

sed 1d <<<"$(cmd pscan -p "x" "$home" "$kvs")" > "$home/pscan.2"

if ! cmp "$home/pscan.1" "$home/pscan.2"; then
    echo "error: prefix scan for [x] failed" >&2
    exit 1
fi

i=1
while (( i <= pfxmax )) ; do
    pfx=$(printf "x%04d" "$i")
    found=$(pscan -c -p "$pfx" "$home" "$kvs" | awk '{print $1}')
    if [ "$found" -ne $((100 * i)) ] ; then
        echo "error: prefix scan [x${i}] failed" >&2
        exit 1
    fi

    i=$((i + 1))
done
