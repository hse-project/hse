#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: simple kvt test (transactional, snapshot isolation)

. common.subr

trap cleanup EXIT
kvdb_create

cpus=$(nproc)

props="-oinodesc=5,datac=13"

cmd kvt -i1000 -T60,$((cpus * 2)) -cv -l8 -m1 "${props}" "$home"
