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
    f"run hse -P workloads/workloade {run_props}".split(),
]

t = YcsbTest(name, cmdlist)

t.execute()
