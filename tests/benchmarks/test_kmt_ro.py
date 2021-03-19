from pathlib import Path

from tools.kmt import KmtTest


name = Path(__file__).stem
args = "-S0 -b -w0 -l1000 -i1000000 -t10"

t = KmtTest(name, args.split())

t.execute()
