#!/usr/bin/env python3

import sys
import hse

hse.Kvdb.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs12")
    kvs = kvdb.kvs_open("kvs12")

    kvs.put(b"a", b"1")
    kvs.put(b"b", b"2")
    kvs.put(b"c", b"3")

    cursor = kvs.cursor()
    revcursor = kvs.cursor(reverse=True)

    kv = cursor.read()
    assert kv == (b"a", b"1")
    kv = revcursor.read()
    assert kv == (b"c", b"3")

    kvs.put(b"d", b"4")

    kv = cursor.read()
    assert kv == (b"b", b"2")
    kv = cursor.read()
    assert kv == (b"c", b"3")
    cursor.read()
    assert cursor.eof

    kv = revcursor.read()
    assert kv == (b"b", b"2")
    kv = revcursor.read()
    assert kv == (b"a", b"1")
    revcursor.read()
    assert revcursor.eof

    cursor.destroy()
    revcursor.destroy()

    cursor = kvs.cursor()
    revcursor = kvs.cursor(reverse=True)

    kv = cursor.read()
    assert kv == (b"a", b"1")
    kv = cursor.read()
    assert kv == (b"b", b"2")
    kv = cursor.read()
    assert kv == (b"c", b"3")
    kv = cursor.read()
    assert kv == (b"d", b"4")
    cursor.read()
    assert cursor.eof

    kv = revcursor.read()
    assert kv == (b"d", b"4")
    kv = revcursor.read()
    assert kv == (b"c", b"3")
    kv = revcursor.read()
    assert kv == (b"b", b"2")
    kv = revcursor.read()
    assert kv == (b"a", b"1")
    revcursor.read()
    assert revcursor.eof

    cursor.destroy()
    revcursor.destroy()

    kvs.put(b"e", b"5")

    cursor = kvs.cursor()
    revcursor = kvs.cursor(reverse=True)

    assert sum(1 for _ in cursor.items()) == 5

    kv = revcursor.read()
    assert kv == (b"e", b"5")
    kv = revcursor.read()
    assert kv == (b"d", b"4")
    kv = revcursor.read()
    assert kv == (b"c", b"3")
    kv = revcursor.read()
    assert kv == (b"b", b"2")
    kv = revcursor.read()
    assert kv == (b"a", b"1")
    revcursor.read()
    assert revcursor.eof

    cursor.destroy()
    revcursor.destroy()
finally:
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop("kvs12")
        kvdb.close()

hse.Kvdb.fini()
