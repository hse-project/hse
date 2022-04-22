#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

#doc: quick longtest focused on cn cursors

. common.subr

trap kvdb_drop EXIT
kvdb_create

kvs=$(kvs_create smoke-0)

threads=4
keys=100000
iter=3
#absolute key min is 6, per longtest command parser
kmin=6
#absolute key max is 8, because rsgen_decode() cannot handle more
kmax=8

cmd longtest "$home" "$kvs" -t "$threads" -i "$iter" -c "$keys" "--kmin=$kmin" "--kmax=$kmax" --cursor
cmd cndb_log -c "$home"
cmd cn_metrics "$home" "$kvs"
