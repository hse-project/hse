#!/usr/bin/env python3

import sys
import random
import time
import struct
import os
import itertools
import yaml


def quit(*lines):
    print(*lines, file=sys.stderr)
    sys.exit(-1)


def keynum2key(keynum):
    return "k_%08x" % keynum


def keynum2key_utf(keynum):
    return bytes(("k_%08x" % keynum), "utf-8")


def rand_sum_array(prng, array_len, sum_value):
    weights = [prng.random() for i in range(array_len)]
    total_weight = sum(weights)
    arr = [int(sum_value * (w / total_weight)) for w in weights]
    curr_sum = sum(arr)
    i = 9
    while curr_sum < sum_value:
        arr[i % array_len] += 1
        curr_sum += 1
        i += 1
    return arr


class KvsetBuilder:
    def __init__(self, xid, final_uniq_keys):
        self.xid = xid
        self.final_uniq_keys = final_uniq_keys
        self.keys = []
        self.curr_uniq_keys = 0


def rand_kvsets(num_kvsets=-1, num_unique_keys=-1, dup_percent=-1, seed=0):  # 0..100

    if seed <= 0:
        seed = int(time.time())

    prng = random.Random()
    prng.seed(seed)

    if num_kvsets <= 0:
        num_kvsets = prng.randint(1, 30)
    if num_unique_keys <= 0:
        num_unique_keys = prng.randint(num_kvsets, 100 * num_kvsets)
    if dup_percent < 0:
        dup_percent = prng.randint(0, 100)

    uniq_key_list = rand_sum_array(prng, num_kvsets, num_unique_keys)
    # print("uniq_key_list: "+repr(uniq_key_list))
    # print("sum(uniq_key_list): "+repr(sum(uniq_key_list)))
    # print("num_kvsets: "+repr(num_kvsets))

    builders = []
    nonfull_kvset_ids = []
    for xid in range(num_kvsets):
        builders.append(KvsetBuilder(xid, uniq_key_list[xid]))
        if uniq_key_list[xid] > 0:
            nonfull_kvset_ids.append(xid)

    # builders[0].keys.append(9)
    # builders[1].keys.append(10)
    # for b in builders:
    #    print("b[{xid}].keys={keys}".format(xid=b.xid,keys=repr(b.keys)))
    # sys.exit(0)

    # print("{0} nonfull_kvset_ids: {1}".format(len(nonfull_kvset_ids), repr(nonfull_kvset_ids)))

    keynum = 0
    while len(nonfull_kvset_ids) > 0:
        keynum += 1
        # randomly pick an index into nonfull_kvset_ids
        nonfull_index = prng.randint(0, len(nonfull_kvset_ids) - 1)
        xid = nonfull_kvset_ids[nonfull_index]
        kvset = builders[xid]
        # print("pick nfi {nfi} from 0..{max}, id {xid} {cur}/{tot}: {keys}".
        #      format(nfi=nonfull_index,
        #             max=len(nonfull_kvset_ids),
        #             cur=kvset.curr_uniq_keys,
        #             tot=kvset.final_uniq_keys,
        #             xid=xid,
        #             keys=repr(kvset.keys)))

        kvset.keys.append(keynum)
        kvset.curr_uniq_keys += 1
        if kvset.curr_uniq_keys == kvset.final_uniq_keys:
            # print("pop nfi {nfi}".format(nfi=nonfull_index))
            nonfull_kvset_ids[nonfull_index] = nonfull_kvset_ids[
                len(nonfull_kvset_ids) - 1
            ]
            nonfull_kvset_ids.pop()

        # can only do dups if xid is not the last kvset
        if (
            dup_percent > 0
            and xid < num_kvsets - 1
            and dup_percent < prng.randint(0, 99)
        ):
            # dup of key in xid must go ito xid2 > xid
            xid2 = prng.randint(xid + 1, num_kvsets - 1)
            builders[xid2].keys.append(-keynum)

    kvsets = []
    for xid in range(num_kvsets):
        kvsets.append(builders[xid].keys)

    return kvsets


class test_collection:
    def __init__(self):
        self.tests = dict()

    def add(self, test):
        tag = test.group + "-" + test.name
        if tag in self.tests:
            quit("test {0} defined twice".format(tag))
        self.tests[tag] = test
        test.write_yaml("{0}.yml".format(tag), "{0}.txt".format(tag))


class test_case:
    def __init__(self, group, name, kvsets, meta={}):
        print("test case: {0}-{1}".format(group, name))
        self.group = group
        self.name = name
        self.kvsets = kvsets
        # meta is a list of tuples
        self.meta = {}
        self.meta["group"] = group
        self.meta["name"] = name
        for k, v in meta.items():
            self.meta[k] = v
        self.compile()

    def check(self):
        unique_keys = dict()
        kvset_number = -1
        for kvset in self.kvsets:
            kvset_number += 1
            key_number = -1
            for key in kvset:
                key_number += 1
                if abs(key) in unique_keys:
                    if key >= 0:
                        orig_kvset_num, orig_key_num = unique_keys[key]
                        print(
                            (
                                "{0}: kvset[{1}].key[{2}] = {3} incorrectly marked as unique\n"
                                + "original entry in kvset {4} key {5}"
                            ).format(
                                self.name,
                                kvset_number,
                                key_number,
                                key,
                                orig_kvset_num,
                                orig_key_num,
                            )
                        )
                        return False
                else:
                    if key < 0:
                        print(
                            "{0}: kvset[{1}].key[{2}] = {3}: incorrectly marked as duplicate".format(
                                self.name, kvset_number, key_number, key
                            )
                        )
                        return False
                    unique_keys[key] = [kvset_number, key_number]
        return True

    def compile(self):

        if not self.check():
            return False

        deduped = []
        test_kvsets = []
        kvset_number = -1
        for kvset in self.kvsets:
            test_kvset = []
            kvset_number += 1
            key_number = -1
            for key in kvset:
                key_number += 1
                if key < 0:
                    key = -key
                    dup = True
                    tag = "_DUP"
                else:
                    dup = False
                    tag = ""

                tuple = (
                    key,
                    bytes(
                        "v_kvset_{kvset}_key_{key}{tag}".format(
                            kvset=kvset_number, key=key_number, tag=tag
                        ),
                        "utf-8",
                    ),
                )

                test_kvset.append(tuple)
                if dup == False:
                    deduped.append(tuple)

            test_kvsets.append(test_kvset)

        self.merged_kvset = sorted(deduped, key=(lambda tup: tup[0]))
        self.test_kvsets = test_kvsets

    def write_yaml(self, yaml_filename, text_filename):
        input_kvsets = []
        i = 0
        for kvset in self.test_kvsets:
            kv = []
            for keynum, val in kvset:
                kv.append([keynum2key(keynum), [[1, "v", val.decode("ascii")]]])
                pass
            input_kvsets.append(kv)
            pass
        kv = []
        for keynum, val in self.merged_kvset:
            kv.append([keynum2key(keynum), [[1, "v", val.decode("ascii")]]])
            pass
        test = {}
        test["_meta"] = self.meta
        test["input_kvsets"] = input_kvsets
        test["output_kvset"] = kv
        # The next step takes an extraordinary amount of time for the big random datasets
        with open(yaml_filename, "w") as fh:
            yaml.safe_dump(test, stream=fh, default_flow_style=False)
            pass


def rand_small_group(coll, group, seed=0, count=25):

    if seed <= 0:
        seed = time.time()
    prng = random.Random()
    prng.seed(seed)

    for i in range(count):
        seed = 1 + int(prng.random() * 1000000)
        num_kvsets = prng.randint(2, 20)
        num_unique_keys = prng.randint(10, 200)
        dup_percent = prng.randint(0, 20)
        kvsets = rand_kvsets(
            num_kvsets=num_kvsets,
            num_unique_keys=num_unique_keys,
            dup_percent=dup_percent,
            seed=seed,
        )
        meta = {
            "seed": seed,
            "num_kvsets": num_kvsets,
            "num_unique_keys": num_unique_keys,
            "dup_percent": dup_percent,
        }
        coll.add(
            test_case(
                group=group, name="rand_{0}".format(seed), kvsets=kvsets, meta=meta
            )
        )


def rand_big_group(coll, group, seed=0, count=10):

    if seed <= 0:
        seed = time.time()
    prng = random.Random()
    prng.seed(seed)

    for i in range(count):
        seed = 1 + int(prng.random() * 1000000)
        num_kvsets = prng.randint(20, 50)
        num_unique_keys = prng.randint(1000, 5000)
        dup_percent = prng.randint(1, 5)
        kvsets = rand_kvsets(
            num_kvsets=num_kvsets,
            num_unique_keys=num_unique_keys,
            dup_percent=dup_percent,
            seed=seed,
        )
        meta = {
            "seed": seed,
            "num_kvsets": num_kvsets,
            "num_unique_keys": num_unique_keys,
            "dup_percent": dup_percent,
        }
        coll.add(
            test_case(
                group=group, name="rand_{0}".format(seed), kvsets=kvsets, meta=meta
            )
        )


coll = test_collection()

group = "empty"
coll.add(test_case(group=group, name="empty0", kvsets=[]))
coll.add(test_case(group=group, name="empty1", kvsets=[[]]))
coll.add(test_case(group=group, name="empty2", kvsets=[[], []]))
coll.add(test_case(group=group, name="empty3", kvsets=[[], [], []]))

group = "crafted"
coll.add(
    test_case(
        group=group,
        name="one_key",
        kvsets=[
            [+1],
            [-1],
            [-1],
        ],
    )
)

coll.add(
    test_case(
        group=group,
        name="one_key_per_kvset1",
        kvsets=[
            [+1],
            [+2],
            [+3],
        ],
    )
)

coll.add(
    test_case(
        group=group,
        name="one_key_per_kvset2",
        kvsets=[
            [+2],
            [+1],
            [+3],
        ],
    )
)

coll.add(
    test_case(
        group=group,
        name="one_key_per_kvset3",
        kvsets=[
            [+3],
            [+2],
            [+1],
        ],
    )
)

coll.add(
    test_case(
        group=group,
        name="interleaved1",
        kvsets=[
            [1, 4, 7, 10],
            [2, 5, 8, 11],
            [3, 6, 9, 12],
        ],
    )
)

coll.add(
    test_case(
        group=group,
        name="interleaved2",
        kvsets=[
            [1, 4, 7, 10],
            [3, 6, 9, 12],
            [2, 5, 8, 11],
        ],
    )
)

coll.add(
    test_case(
        group=group,
        name="ordered1",
        kvsets=[
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            [9, 10, 11, 12],
        ],
    )
)


coll.add(
    test_case(
        group=group,
        name="head_dups1",
        kvsets=[
            [+1, +2, +3],
            [-1, -2, -3],
            [-1, -2, -3],
        ],
    )
)

coll.add(
    test_case(
        group=group,
        name="head_dups2",
        kvsets=[
            [+1, +2, +3],
            [-1, -2, -3],
            [-1, -2, -3],
        ],
    )
)

coll.add(
    test_case(
        group=group,
        name="cross_kvset_dups1",
        kvsets=[
            [+1, +2],
            [-2, +3],
            [-3, +4],
            [-4],
        ],
    )
)

coll.add(
    test_case(
        group=group,
        name="cross_kvset_dups2",
        kvsets=[
            [+1, +2],
            [-2, +3],
            [-3, +4],
            [-4],
        ],
    )
)

coll.add(
    test_case(
        group=group,
        name="sequential1",
        kvsets=[
            [+1, +2, +3],
            [+4, +5, +6],
        ],
    )
)

coll.add(
    test_case(
        group=group,
        name="sequential2",
        kvsets=[
            [+1, +2, +3],
            [-1, -2, -3, +4, +5, +6],
        ],
    )
)


coll.add(
    test_case(
        group=group,
        name="triangle1",
        kvsets=[
            [+1],
            [-1, +2],
            [-1, -2, +3],
            [-1, -2, -3, +4],
        ],
    )
)

coll.add(
    test_case(
        group=group,
        name="long_short1",
        kvsets=[
            [+1, +2, +3, +4, +5],
            [+6],
            [+7, +8, +9, +10, +11, +12],
            [+13],
            [+14, +15, +16, +17, +18],
        ],
    )
)

coll.add(
    test_case(
        group=group,
        name="end_front_dup1",
        kvsets=[[+1, +2, +3], [-3, +4, +5], [-5, +6, +7], [-7, +9]],
    )
)

rand_small_group(coll, group="rand_small", seed=1234)
rand_big_group(coll, group="rand_big", seed=5678)
