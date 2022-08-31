#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

#doc: test to verify absolute and relative path handling in kvdb create, storage add and kvdb meta.

. common.subr

pdir="$home/paths"
cmd mkdir -p "$pdir"
cmd pushd "$pdir"

for homedir in . ./ $pdir kvdb1 ./kvdb1 kvdb1/../ $pdir/kvdb1 $pdir/$pdir/$pdir test1/test1/test1 test1/test1/../test1
do
    cmd mkdir -p "$homedir"

    cmd hse kvdb create "$homedir"
    cmd [ "$(cmd jq -r .storage.capacity.path "$homedir/kvdb.meta")" = "capacity" ]
    cmd hse kvdb drop "$homedir"

    cmd mkdir -p "$homedir/data/capacity"
    cmd hse kvdb create "$homedir" storage.capacity.path=data/capacity
    cmd [ "$(cmd jq -r .storage.capacity.path "$homedir/kvdb.meta")" = "data/capacity" ]
    cmd hse kvdb drop "$homedir"

    cmd mkdir -p "$homedir/../data/capacity"
    cmd hse kvdb create "$homedir" storage.capacity.path=../data/capacity
    cmd [ "$(cmd jq -r .storage.capacity.path "$homedir/kvdb.meta")" = "../data/capacity" ]
    cmd hse kvdb drop "$homedir"

    cmd mkdir -p "$home/$homedir/data/capacity"
    cmd hse kvdb create "$homedir" "storage.capacity.path=$home/$homedir/data/capacity"
    cmd [ "$(cmd jq -r .storage.capacity.path "$homedir/kvdb.meta")" = "$home/$homedir/data/capacity" ]
    cmd hse kvdb drop "$homedir"

    cmd mkdir -p "$homedir/data/capacity" "$homedir/data/staging"
    cmd hse kvdb create "$homedir" storage.capacity.path=data/capacity storage.staging.path=data/staging
    cmd [ "$(cmd jq -r .storage.capacity.path "$homedir/kvdb.meta")" = "data/capacity" ]
    cmd [ "$(cmd jq -r .storage.staging.path "$homedir/kvdb.meta")" = "data/staging" ]
    cmd hse kvdb drop "$homedir"

    cmd hse kvdb create "$homedir" storage.capacity.path=data/capacity
    cmd hse storage add "$homedir" storage.staging.path=data/staging
    cmd [ "$(cmd jq -r .storage.capacity.path "$homedir/kvdb.meta")" = "data/capacity" ]
    cmd [ "$(cmd jq -r .storage.staging.path "$homedir/kvdb.meta")" = "data/staging" ]
    cmd hse kvdb drop "$homedir"

    cmd mkdir -p "$homedir/../data/capacity" "$homedir/../data/staging"
    cmd hse kvdb create "$homedir" storage.capacity.path=../data/capacity storage.staging.path=../data/staging
    cmd [ "$(cmd jq -r .storage.capacity.path "$homedir/kvdb.meta")" = "../data/capacity" ]
    cmd [ "$(cmd jq -r .storage.staging.path "$homedir/kvdb.meta")" = "../data/staging" ]
    cmd hse kvdb drop "$homedir"

    cmd hse kvdb create "$homedir" storage.capacity.path=../data/capacity
    cmd hse storage add "$homedir" storage.staging.path=../data/staging
    cmd [ "$(cmd jq -r .storage.capacity.path "$homedir/kvdb.meta")" = "../data/capacity" ]
    cmd [ "$(cmd jq -r .storage.staging.path "$homedir/kvdb.meta")" = "../data/staging" ]
    cmd hse kvdb drop "$homedir"

    cmd mkdir -p "$home/data/capacity" "$home/data/staging"
    cmd hse kvdb create "$homedir" storage.capacity.path="$home/data/capacity" storage.staging.path="$home/data/staging"
    cmd [ "$(cmd jq -r .storage.capacity.path "$homedir/kvdb.meta")" = "$home/data/capacity" ]
    cmd [ "$(cmd jq -r .storage.staging.path "$homedir/kvdb.meta")" = "$home/data/staging" ]
    cmd hse kvdb drop "$homedir"

    cmd hse kvdb create "$homedir" storage.capacity.path="$home/data/capacity"
    cmd hse storage add "$homedir" storage.staging.path="$home/data/staging"
    cmd [ "$(cmd jq -r .storage.capacity.path "$homedir/kvdb.meta")" = "$home/data/capacity" ]
    cmd [ "$(cmd jq -r .storage.staging.path "$homedir/kvdb.meta")" = "$home/data/staging" ]
    cmd hse kvdb drop "$homedir"
done
