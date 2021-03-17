from pathlib import Path

from tools.kmt import KmtOptions, KmtTest


test_name = Path(__file__).stem

kmt_options = KmtOptions(
    seed=1, wpct=0, kbinsz=8, vlenmax=1000, recmax=1000000, swsecs=10,
)

t = KmtTest(test_name, kmt_options)
t.execute()
