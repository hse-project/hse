#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: simple kvt test (non-transactional)

. common.subr

trap kvdb_drop EXIT
kvdb_create

# kvdb/kvs test

props="-oinodesc=3,datac=7"

cmd kvt -i1m -t15 -cv -m1 "${props}" "$home"
