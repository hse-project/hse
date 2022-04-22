#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.

#doc: kvt compression test (transactional, snapshot isolation)

. common.subr

trap kvdb_drop EXIT
kvdb_create

jobs=$(($(nproc) / 4 + 3))

props="-oinodesc=3,datac=7"

cmd kvt -i1m  "-T30,${jobs}" -cvvv -l0,16k -m1 -ovrunlen=32  -ovcomp=1 "${props}" "${home}"
cmd kvt -Fi7k "-T30,${jobs}" -cvvv -l1m    -m1 -ovrunlen=331 -ovcomp=1 "${props}" "${home}"
cmd kvt -Fi5m "-T17,${jobs}" -cvvv -l0,16  -m1 -ovrunlen=1   -ovcomp=1 "${props}" "${home}"
cmd kvt "-T17,${jobs}" -cvvv -m1 "${props}" "${home}"
