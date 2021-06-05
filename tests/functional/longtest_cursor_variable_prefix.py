#!/usr/bin/env python3
import hse
from kvpy.util import ensure_kvs
import kvpy.util as util
import sys
import subprocess
# run longtest --cursor with different prefix lengths

#
# Notes:
# When running with cursor option the kmin and kmax need to be <8
# The default value if not specified is 20 and 30 respectively.
# key len 1-7 errors out as too small, so starting running with 9
# Leaving it as a list since the behaviour might change

kvs_name = 'longtest_cursor_variable_pfx'
kvdb_name = sys.argv[1]

longtest_duration = 600

hse.init()
p = hse.Params()

pfxlens = [8]

for pfxlen in pfxlens:
    realkvsname = kvs_name + str(pfxlen)
    p.set(key="kvs.pfx_len", value=str(pfxlen))
    with util.create_kvdb(kvdb_name, p) as kvdb:
        ensure_kvs(kvdb, realkvsname, p)
    cmd = f'longtest --cursor --klen {pfxlen} -s{longtest_duration} {kvdb_name} {realkvsname}'
    subprocess.run(cmd.split(), check=True)

hse.fini()
