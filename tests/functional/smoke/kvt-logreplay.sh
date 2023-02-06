#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: simple kvt c1 logreplay crash test (transactional, snapshot isolation)

. common.subr

trap cleanup EXIT
kvdb_create

cpus=$(nproc)

props="-oinodesc=3,datac=7"

cmd kvt -i1m "${props}" "$home"
cmd -s 9 kvt -T60,$((cpus * 2)) -ccv -l8 -m1 -K9,10,20 "${props}" "$home"
cmd -s 9 kvt -T60,$((cpus * 2)) -ccv -l8 -m1 -K9,15,25 "${props}" "$home"

cmd kvt -cv "${props}" "$home"
