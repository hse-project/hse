#!/usr/bin/env python3
import hse
from kvpy.util import ensure_kvs
import kvpy.util as util
import sys
import subprocess
from tree import collect_metrics

# run kmt on kvs's on same mpool with and without compression

def run_kmt(kvdb_name: str, kvs_name: str, compression: bool = False, compact: bool = False, kmt_record_count: int = 1000):
    """
    run kmt with requested params, compact kvdb and return avg tree valuen len
    """

    args = '-s1 -j48 -b -w 50 -l 4000:4000 -S 100'
    end_args = '-o rvalrunlen=128'
    
    if compression:
        end_args += f' kvs.value_compression={compression}'
    
    cmd = f'kmt {args} -i {kmt_record_count} {kvdb_name}/{kvs_name} {end_args}'

    subprocess.run(cmd.split(), check=True)

    cmd = f'kmt {args} -c {kvdb_name}/{kvs_name} {end_args}'

    subprocess.run(cmd.split(), check=True)

    if compact:
        cmd = f'hse1 kvdb compact -t 300 {kvdb_name}'
        subprocess.run(cmd.split(), check=True)

    avg_tree_vlen = collect_metrics(kvdb_name, kvs_name)
    return avg_tree_vlen


kvs_name1 = 'kvs_compression_same_mpool1'
kvs_name2 = 'kvs_compression_same_mpool2'
kvdb_name = sys.argv[1]

hse.init()

p = hse.Params()

with util.create_kvdb(kvdb_name, p) as kvdb:
    ensure_kvs(kvdb, kvs_name1, p)

vlen_comp = run_kmt(kvdb_name, kvs_name1, compression='lz4', compact=False)

with util.create_kvdb(kvdb_name, p) as kvdb:
    ensure_kvs(kvdb, kvs_name2, p)

vlen_nocomp = run_kmt(kvdb_name, kvs_name2, compression=None, compact=False)

assert vlen_comp < vlen_nocomp

hse.fini()
