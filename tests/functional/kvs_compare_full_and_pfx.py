#!/usr/bin/env python3
import hse
import sys

# Verify a case where full scan and pfx scan return equivalent results

keycount = 10*1024*1024

for pfxlen in range(4):
    try:
        kvsname = f'compare_full_and_pfx{pfxlen}'

        hse.init()

        kvdb = hse.Kvdb.open(sys.argv[1])

        p = hse.Params().set("kvs.pfx_len", str(pfxlen))

        kvdb.kvs_make(kvsname, params=p)
        kvs = kvdb.kvs_open(kvsname)

        for i in range(keycount):
            if i % 2 == 0:
                key = f'XXXX{i}'.encode()
            else:
                key = f'CCCC{i}'.encode()
            kvs.put(key, None)

        with kvs.cursor() as c1:
            s1 = sum(1 for _ in c1.items())
        with kvs.cursor(b'CCCC') as c2:
            s2 = sum(1 for _ in c2.items())

        assert s1 == keycount
        assert s2 == keycount / 2
    finally:
        if kvs:
            kvs.close()
        if kvdb:
            kvdb.kvs_drop(kvsname)
            kvdb.close()
        hse.fini()
