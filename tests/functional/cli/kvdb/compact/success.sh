#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

. common.subr

trap cleanup EXIT
kvdb_create

cmd hse kvdb compact --timeout 300 "$home"
cmd hse kvdb compact --status "$home"
cmd hse kvdb compact --cancel "$home"
