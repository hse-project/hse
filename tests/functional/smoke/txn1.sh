#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: simple transaction test on a KVDB kvs

. common.subr

trap cleanup EXIT
kvdb_create

kvs1=$(kvs_create smoke-0)

cmd ctxn_validation "$home" "$kvs1"
cmd ctxn_validation -i7 "$home" "$kvs1"
cmd ctxn_validation -i17 "$home" "$kvs1"
cmd ctxn_validation -i17 -K13 "$home" "$kvs1"
cmd ctxn_validation -i34 -K13 "$home" "$kvs1"
cmd ctxn_validation -s -k1 "$home" "$kvs1"
cmd ctxn_validation -s -i9 -k1 "$home" "$kvs1"
cmd ctxn_validation -s -i19 -k1000 "$home" "$kvs1"
cmd ctxn_validation -s -i5555 -k1 "$home" "$kvs1"
cmd ctxn_validation -s -i6666 -k7 "$home" "$kvs1"
cmd ctxn_validation -s -i9999 -k173 "$home" "$kvs1"
cmd ctxn_validation -c -i5 -k173 "$home" "$kvs1"
cmd ctxn_validation -p pc -k1 "$home" "$kvs1"
cmd ctxn_validation -p pc -k3 "$home" "$kvs1"
cmd ctxn_validation -p pc -i1234 -k0 "$home" "$kvs1"
cmd ctxn_validation -p pc -i1234 -k1 "$home" "$kvs1"
cmd ctxn_validation -p pc -i1234 -k1 -r "$home" "$kvs1"
cmd ctxn_validation -p pc -i1234 -k1 -j64 "$home" "$kvs1"
cmd ctxn_validation -p gc -i1234 -k1 -j64 "$home" "$kvs1"
cmd ctxn_validation -p pa -i5 -k1 -j64 "$home" "$kvs1"
cmd ctxn_validation -p ga -i5 -k1 -j64 "$home" "$kvs1"
cmd ctxn_validation -p pc -i1234 -k1 -r -j64 "$home" "$kvs1"
cmd ctxn_validation -p gc -i1234 -k1 -r -j64 "$home" "$kvs1"
cmd ctxn_validation -p pa -i5 -k1 -r -j64 "$home" "$kvs1"
cmd ctxn_validation -p ga -i5 -k1 -r -j64 "$home" "$kvs1"
cmd ctxn_validation -p pc -i1234 -k7 -r -j333 "$home" "$kvs1"
cmd ctxn_validation "$home" "$kvs1"
