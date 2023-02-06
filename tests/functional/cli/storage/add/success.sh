#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

. common.subr

trap cleanup EXIT
kvdb_create

mkdir "$home/staging"
cmd hse storage add "$home" "storage.staging.path=$home/staging"
