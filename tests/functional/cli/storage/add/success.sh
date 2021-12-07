#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

cleanup() {
    kvdb_drop
    rm -rf "$home/staging"
}

trap cleanup EXIT

kvdb_create

mkdir "$home/staging"
cmd hse storage add "$home" "storage.staging.path=$home/staging"
