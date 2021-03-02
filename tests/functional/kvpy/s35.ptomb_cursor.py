#!/usr/bin/env python3

import sys
from hse import Kvdb, Params, Kvs


def verify(kvs: Kvs, pfx: str, cnt: int):
    # [HSE_REVISIT] Getting all keys is too slaw/freezes
    get_cnt = 100
    if cnt < get_cnt:
        get_cnt = cnt

    for i in range(get_cnt):
        k = "{}-{:028}".format(pfx, i)
        val = kvs.get(k.encode())
        assert val != None
        assert val.decode() == k

    with kvs.cursor(pfx.encode()) as c:
        assert sum(1 for _ in c.items()) == cnt

    with kvs.cursor(pfx.encode(), reverse=True) as rc:
        assert sum(1 for _ in rc.items()) == cnt

    # create, seek, reads
    with kvs.cursor(pfx.encode()) as c:
        c.seek(pfx.encode())
        assert sum(1 for _ in c.items()) == cnt

    with kvs.cursor(pfx.encode(), reverse=True) as rc:
        # Bump up the last character so prefix is larger than all keys
        ch = pfx[-1]
        i = ord(ch[0])
        i += 1
        seek_key = pfx[:-1] + chr(i)

        rc.seek(seek_key.encode())
        assert sum(1 for _ in rc.items()) == cnt


Kvdb.init()

p = Params()
p.set(key="kvdb.dur_enable", value="0")  # So sync forces an ingest
p.set(key="kvs.pfx_len", value="4")
p.set(key="kvs.cn_maint_disable", value="1")

# Test 1: Update after seek. Seek can be to an existing key or non-existent key
kvdb = Kvdb.open(sys.argv[1], params=p)
kvdb.kvs_make("kvs35", params=p)
kvs = kvdb.kvs_open("kvs35", params=p)

kvs.put(b"AAAA1", b"1")
kvdb.sync()
kvs.prefix_delete(b"AAAA")  # kvset with only ptomb

verify(kvs=kvs, pfx="AAAA", cnt=0)
assert kvs.get(b"AAAA1") == None

kvdb.sync()
verify(kvs=kvs, pfx="AAAA", cnt=0)
assert kvs.get(b"AAAA1") == None

c = kvs.cursor(b"AAAA")
c.seek(b"AAAA1")
c.destroy()


# This combination of number of keys and key length fills up almost the
# entire wbtree (main).
nkeys = 1767013
nptombs = 10

# Kvset with all ptombs < keys
for i in range(nkeys):
    k = "CCCC-{:028}".format(i)
    kvs.put(k.encode(), k.encode())

for i in range(nptombs):
    pfx = f"BBB{i}"
    kvs.prefix_delete(pfx.encode())

verify(kvs=kvs, pfx="CCCC", cnt=nkeys)
kvdb.sync()

verify(kvs=kvs, pfx="CCCC", cnt=nkeys)

# Kvset with all ptombs > keys
for i in range(nkeys):
    k = "DDDD-{:028}".format(i)
    kvs.put(k.encode(), k.encode())

for i in range(nptombs):
    pfx = f"EEE{i}"
    kvs.prefix_delete(pfx.encode())

verify(kvs=kvs, pfx="DDDD", cnt=nkeys)
kvdb.sync()

verify(kvs=kvs, pfx="DDDD", cnt=nkeys)

kvs.close()
kvdb.close()
Kvdb.fini()
