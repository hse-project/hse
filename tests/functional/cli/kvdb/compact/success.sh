#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

. common.subr

trap cleanup EXIT
kvdb_create

cmd hse kvdb compact --timeout 300 "$home"
cmd hse kvdb compact --status "$home"
cmd hse kvdb compact --cancel "$home"
