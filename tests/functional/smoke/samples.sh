#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: samples test

. common.subr

fbase="$home/large_val"

end () {
    rm -fr "$fbase"*
    cleanup
}

trap end EXIT

cmd ex1_create "$home" skvs0 skvs1 skvs2 skvs3 skvs4
cmd ex2_simple_ops "$home" skvs0
cmd ex3_cursor "$home" skvs1
cmd ex4_transactions "$home" skvs2 skvs3
cmd ex6_error_handling
cmd ex7_configuration "$home"

for ((n=1; n<10; n++)); do
    cmd dd bs=1000000 count="$n" if=/dev/urandom of="$fbase$n"
done

cmd ex5_large_val "$home" skvs4 "$fbase"*
cmd ex5_large_val "$home" skvs4 -x "$fbase"*
cmd chmod 644 "$fbase"*.out

for ((n=1; n<10; n++)); do
    cmd cmp "$fbase$n" "$fbase$n.out"
done
