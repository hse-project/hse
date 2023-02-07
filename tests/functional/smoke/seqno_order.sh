#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

. common.subr

trap cleanup EXIT
kvdb_create

# one thread does transactional PUTs while another periodically calls flush
kvs=$(kvs_create smoke-0)
cmd txput_flush "$home" "$kvs"
