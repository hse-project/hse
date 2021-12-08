#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: test to verify absolute and relative path handling in kvdb create, storage add and kvdb meta.

. "$(dirname "${BASH_SOURCE[0]}")/smoke.subr"

pdir="$home"/paths
cmd mkdir -p "$pdir"
cmd cd "$pdir"

for homedir in . ./ $pdir kvdb1 ./kvdb1 kvdb1/../ $pdir/kvdb1 $pdir/$pdir/$pdir test1/test1/test1 test1/test1/../test1
do
    cmd mkdir -p "$homedir"

    cmd hse kvdb create "$homedir"
    cmd hse kvdb drop "$homedir"

    cmd mkdir -p "$homedir/data/capacity"
    cmd hse kvdb create "$homedir" storage.capacity.path=data/capacity
    cmd hse kvdb drop "$homedir"

    cmd mkdir -p "$homedir/../data/capacity"
    cmd hse kvdb create "$homedir" storage.capacity.path=../data/capacity
    cmd hse kvdb drop "$homedir"

    cmd mkdir -p "$home/$homedir/data/capacity"
    cmd hse kvdb create "$homedir" "storage.capacity.path=$home/$homedir/data/capacity"
    cmd hse kvdb drop "$homedir"

    cmd mkdir -p "$homedir/data/capacity" "$homedir/data/staging"
    cmd hse kvdb create "$homedir" storage.capacity.path=data/capacity storage.staging.path=data/staging
    cmd hse kvdb drop "$homedir"

    cmd hse kvdb create "$homedir" storage.capacity.path=data/capacity
    cmd hse storage add "$homedir" storage.staging.path=data/staging
    cmd hse kvdb drop "$homedir"

    cmd mkdir -p "$homedir/../data/capacity" "$homedir/../data/staging"
    cmd hse kvdb create "$homedir" storage.capacity.path=../data/capacity storage.staging.path=../data/staging
    cmd hse kvdb drop "$homedir"

    cmd hse kvdb create "$homedir" storage.capacity.path=../data/capacity
    cmd hse storage add "$homedir" storage.staging.path=../data/staging
    cmd hse kvdb drop "$homedir"

    cmd mkdir -p "$home/data/capacity" "$home/data/staging"
    cmd hse kvdb create "$homedir" storage.capacity.path="$home/data/capacity" storage.staging.path="$home/data/staging"
    cmd hse kvdb drop "$homedir"

    cmd hse kvdb create "$homedir" storage.capacity.path="$home/data/capacity"
    cmd hse storage add "$homedir" storage.staging.path="$home/data/staging"
    cmd hse kvdb drop "$homedir"
done
