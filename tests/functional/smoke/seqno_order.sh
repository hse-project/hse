#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

. common.subr

trap cleanup EXIT
kvdb_create

# one thread does transactional PUTs while another periodically calls flush
kvs=$(kvs_create smoke-0)
cmd txput_flush "$home" "$kvs"
