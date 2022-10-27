#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2022 Micron Technology, Inc. All rights reserved.

#doc: test behavior of kvdb open modes (rdonly, rdonly_replay, diag, rdwr)

. common.subr

trap kvdb_drop EXIT
kvdb_create

props="-oinodesc=2,datac=2"

# Load 1024 records
kvt -i1k -cv -m1 "$props" "$home"

# PUTs must fail on a KVDB opened in the following modes
modes="rdonly rdonly_replay diag"
for mode in $modes
do
    cmd -e kvt -T5,4 -l8 -m1 "$props" "$home" kvdb-oparms mode="$mode"
done

# Success
cmd kvt -T5,4 -cv -l8 -m1 "$props" "$home"

# GETs must succeed on a KVDB opened in the following modes
modes="rdonly rdonly_replay diag"
for mode in $modes
do
    cmd kvt -cv -m1 "$props" "$home" kvdb-oparms mode="$mode"
done

# Restricting write permission on $home works only for a non-root user
if [[ $(id -u) -ne 0 ]]; then
    # Remove write permission from $home
    omode=$(stat -c %a "$home")
    cmd chmod 555 "$home"

    # PUTs must fail
    cmd -e kvt -T5,4 -l8 -m1 "$props" "$home"

    # Cannot open KVDB in the following modes without write permission on $home
    modes="rdonly_replay rdwr"
    for mode in $modes
    do
        cmd -e kvt -cv -m1 "$props" "$home" kvdb-oparms mode="$mode"
    done

    # GETs must succeed on a KVDB opened in the following modes without write permission on $home
    modes="rdonly diag"
    for mode in $modes
    do
        cmd kvt -cv -m1 "$props" "$home" kvdb-oparms mode="$mode"
    done
    cmd chmod "$omode" "$home"

    # Remove write permission from $home/capacity
    omode=$(stat -c %a "$home"/capacity)
    cmd chmod 555 "$home"/capacity

    # PUTs must fail
    cmd -e kvt -T5,4 -l8 -m1 "$props" "$home"

    # Cannot open KVDB in the following modes without write permission on the capacity FS
    modes="rdonly_replay rdwr"
    for mode in $modes
    do
        cmd -e kvt -cv -m1 "$props" "$home" kvdb-oparms mode="$mode"
    done

    # GETs must succeed on a KVDB opened in the following modes without write perm on capacity FS
    modes="rdonly diag"
    for mode in $modes
    do
        cmd kvt -cv -m1 "$props" "$home" kvdb-oparms mode="$mode"
    done
    cmd chmod "$omode" "$home"/capacity
fi

# Force the KVDB into dirty state by crashing kvt
cmd -s 9 kvt -T30,4 -l8 -m1 -K9,5,7 "${props}" "$home"

# Cannot open KVDB in rdonly mode w/ dirty WAL
cmd -e kvt -cv "$props" "$home" kvdb-oparms mode=rdonly

# diag mode skips dirty wal. The other two modes replays WAL at open
modes="diag rdonly_replay rdwr"
for mode in $modes
do
    cmd kvt -cv "$props" "$home" kvdb-oparms mode="$mode"
done
