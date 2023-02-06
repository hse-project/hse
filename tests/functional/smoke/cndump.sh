#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: cndump test

. common.subr

trap cleanup EXIT
kvdb_create

kvs=$(kvs_create smoke-0)

cmd putbin -c10 -L100 "$home" "$kvs"

cmd cndump -h
cmd cndump -hv

cmd cndump cndb "$home" > "$home/tmp.cndb"

cmd awk '($1=="kvset_add") {for(i=2;i<NF;i+=2){if($i=="kvsetid"){print($(i+1))}}}' < "$home/tmp.cndb" > "$home/tmp.kvset"
cmd awk '($1=="hblock")    {print($2)}' < "$home/tmp.cndb" > "$home/tmp.hblock"
cmd awk '($1=="kblocks")   {print($3)}' < "$home/tmp.cndb" > "$home/tmp.kblock"
cmd awk '($1=="vblocks")   {print($3)}' < "$home/tmp.cndb" > "$home/tmp.vblock"

kvset=$(cmd  cat "$home/tmp.kvset")
hblock=$(cmd cat "$home/tmp.hblock")
kblock=$(cmd cat "$home/tmp.kblock")
vblock=$(cmd cat "$home/tmp.vblock")

cmd cndump kvset  "$home" "$kvset"
cmd cndump mblock "$home" "$hblock"
cmd cndump mblock "$home" "$kblock"
cmd cndump mblock "$home" "$vblock"
