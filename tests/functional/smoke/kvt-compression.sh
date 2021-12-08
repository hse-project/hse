#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: kvt compression test (transactional, snapshot isolation)

. "$(dirname "${BASH_SOURCE[0]}")/smoke.subr"

trap kvdb_drop EXIT
kvdb_create

cpus=$(nproc)

props="-oinodesc=3,datac=7"

cmd kvt -i1m  -T30,$((cpus * 2)) -cvvv -l0,16k -m1 -ovrunlen=32  -ovcomp=1 "${props}" "${home}"
cmd kvt -Fi7k -T30,$((cpus * 2)) -cvvv -l1m    -m1 -ovrunlen=331 -ovcomp=1 "${props}" "${home}"
cmd kvt -Fi5m -T17,$((cpus * 2)) -cvvv -l0,16  -m1 -ovrunlen=1   -ovcomp=1 "${props}" "${home}"
cmd kvt -T17,$((cpus * 2)) -cvvv -m1 "${props}" "${home}"
