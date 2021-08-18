# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

from pathlib import Path

from tools.dbbench import DBbenchTest

name = Path(__file__).stem
cli_params = "--num=900000000 --threads=32 --value_size=400"
cmdlist = [
    f"--benchmarks=fillseq {cli_params} --histogram=1".split(),
    f"--benchmarks=overwrite --use_existing_db=1 {cli_params} --histogram=1".split(),
    f"--benchmarks=readwhilewriting --use_existing_db=1 {cli_params} --histogram=1".split(),
    f"--benchmarks=readrandom --use_existing_db=1 {cli_params} --histogram=1".split(),
]
t = DBbenchTest(name, cmdlist)

t.execute()
