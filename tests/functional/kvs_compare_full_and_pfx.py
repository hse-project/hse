#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

from utility import cli, lifecycle

from hse3 import hse

# Verify a case where full scan and pfx scan return equivalent results

keycount = 10 * 1024 * 1024

hse.init(cli.CONFIG)

try:
    with lifecycle.KvdbContext() as kvdb:
        for pfxlen in range(4):
            with lifecycle.KvsContext(kvdb, f"compare_full_and_pfx{pfxlen}") as kvs:
                for i in range(keycount):
                    if i % 2 == 0:
                        key = f"XXXX{i}".encode()
                    else:
                        key = f"CCCC{i}".encode()
                    kvs.put(key, None)

                with kvs.cursor() as c1:
                    s1 = sum(1 for _ in c1.items())
                with kvs.cursor(b"CCCC") as c2:
                    s2 = sum(1 for _ in c2.items())

                assert s1 == keycount
                assert s2 == keycount / 2
finally:
    hse.fini()
