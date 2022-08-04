#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

# Prefix trees switch from prefix spilling to full key spilling when
# spilling from a level with at least 1024 nodes;
#
# Nodes at each level for different fanouts:
#
#    Tree Level   Fanout=2    Fanout=4    Fanout=8    Fanout=16
#    ----------   --------    --------    --------    ---------
#    Root   0          1           1           1            1
#    Level  1          2           4           8           16
#    Level  2          4          16          64        **256**
#    Level  3          8          64       **512***      4096
#    Level  4         16       **256**      4096        65536
#    Level  5         32        1024       32768
#    Level  6         64        4096
#    Level  7      **128**     16384
#    Level  8        256       65536
#    Level  9        512
#    Level  10      1024
#    Level  11      2048
#    Level  12      4096
#


# Test logic
# -----------
# For each fanout:
#   - Set max node size to 32MiB to enable faster testing with less data.
#   - Create prefix tree.
#   - Ingest significantly more than 32MiB data (eg, 2 X 32 Mib).
#   - Run putbin in idle mode to let tree take final form
#   - Verify tree shape

. common.subr

trap kvdb_drop EXIT
kvdb_create

(( size = 32 << 20))
(( klen = 20  ))
(( vlen = 100 ))
(( nkeys = 2 * size / (klen + vlen) ))

oparms=(
    kvdb-oparms
    csched_debug_mask=0x30
    csched_rspill_params=0x01ff
    csched_leaf_comp_params=0x0001ff
    csched_qthreads=0x080808
    kvs-oparms
    cn_close_wait=true
    cn_split_size=32)

for fanout in 2 4 8 16; do
    # shellcheck disable=SC2034
    case $fanout in
        (2)  lvl=7;;
        (4)  lvl=4;;
        (8)  lvl=3;;
        (16) lvl=2;;
        *) exit 2;;
    esac

    kvs=$(kvs_create smoke-"$fanout" prefix.length=4)


    cmd kmt -j32 -f 'xxxx%016lx' "-l$vlen:$vlen" -s1 "-i$nkeys" "$home" "$kvs" "${oparms[@]}"

    cmd putbin -n 5000 "$home" "$kvs" "${oparms[@]}"

    cmd cn_metrics "$home" "$kvs"

    # TODO: verify tree shape, remove shellcheck directive above
    #metrics_log=$LOG
    #cmd grep "^n $lvl," $metrics_log
    #cmd -e grep "^n $((lvl+1))," $metrics_log
done
