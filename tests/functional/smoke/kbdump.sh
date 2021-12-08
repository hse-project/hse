#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: cn_kbdump test

. "$(dirname "${BASH_SOURCE[0]}")/smoke.subr"

kbid="doesnotexist"

cleanup() {
    rm -f "$home/K000.${kbid}.gz"
    kvdb_drop
}

trap cleanup EXIT

kvdb_create

keys=1000
kvs=$(kvs_create smoke-0) || exit $?
cmd simple_client "$home" "$kvs" -c "$keys" -v

kbid=$(cn_metrics "$home" "$kvs" | awk '$1 == "k" {print $16}')
cmd cn_kbdump -w "$home" "$home/capacity" "${kbid}" "${kbid}"
cmd cn_kbdump -r "$home/K000.${kbid}.gz"
