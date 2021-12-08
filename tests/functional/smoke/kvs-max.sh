#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: ensure we can create 256 kvs'

. "$(dirname "${BASH_SOURCE[0]}")/smoke.subr"

trap kvdb_drop EXIT
kvdb_create

typeset -i i=256

while (( i>0 )) ; do
    i=$((i-1))
    kvs_create "kvs$i" || exit $?
done

cmd kmt -i1k -t5 -cx -s1 "$home" "kvs$i"
