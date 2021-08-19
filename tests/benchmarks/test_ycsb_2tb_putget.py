# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

from pathlib import Path

from tools.ycsb import YcsbTest


operationcount = 2000 * 1000 * 1000
recordcount = 2000 * 1000 * 1000

field_props = "-p fieldcount=1 -p fieldlength=1000"
load_props = f"{field_props} -p recordcount={recordcount}"
run_props = (
    f"{field_props} -p recordcount={recordcount} -p operationcount={operationcount}"
)

name = Path(__file__).stem
cmdlist = [
    f"load hse -P workloads/workloada {load_props}".split(),
    f"run hse -P workloads/workloada {run_props}".split(),
    f"run hse -P workloads/workloadb {run_props}".split(),
    f"run hse -P workloads/workloadc {run_props}".split(),
    f"run hse -P workloads/workloadf {run_props}".split(),
    f"run hse -P workloads/workloadd {run_props}".split(),
]

t = YcsbTest(name, cmdlist)

t.execute()
