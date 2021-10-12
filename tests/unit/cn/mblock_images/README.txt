This directory contains binary images of kblocks and vblocks which are used
by several unit tests.  The file naming scheme is:

    ${dataset}.${kblock_version}    // kblocks
    ${dataset}.${vblock_version}    // vblocks

Kblocks have a three part version identifier that consists of the kblock
header version number, the wbtree version number and the bloom version number.
For example, "kb3_w2_b3" identifies kblock header version 3, wbtree version 2
and bloom version 3.

Here's a rundown of the data files in this directory:

    Kblock and vblock with 100 keys, created with simple_client:

        simple_100a.kb3_w2_b3
        simple_100a.vb1

    Kblock and vblock with 100 keys, created with simple_client, updated for
    wbtree version 3:

        simple_100b.kb3_w3_b3
        simple_100b.vb1

    Kblock and vblock with 100 keys and 4 values per key, created with ctxn_validation:

        multival_100keys_4vals.kb3_w3_b3.xz
        multival_100keys_4vals.vb1.xz

    Kblock and vblock with 10 keys and 2000 values per key, created with ctxn_validation:

        multival_10keys_2000vals.kb3_w3_b3.xz
        multival_10keys_2000vals.vb1.xz


How to create new versions of these files
-----------------------------------------

The command line syntax for these tools may have changed from what is
documented here.  Use these instructions as a guide and update them
accordingly.

1. Create a new KVS and put 1031 keys

    hse kvdb create /mnt/kvdb/kvdb1
    hse kvs create /mnt/kvdb/kvdb1 kvs1

    simple_client /mnt/kvdb/kvdb1 kvs1 -c 1031 -v -f"key.%09d"

2. Dump the cn metadata log to see the kblock and vblock IDs:

    cn_metrics /mnt/kvdb/kvdb1 kvs1
    cn_kbdump -s /mnt/kvdb/kvdb1/capacity 0x102400000 0x102400000

Sample output:

    $ cn_metrics /mnt/kvdb/kvdb1 kvs1
    H Loc           Dgen    Keys   Tombs AvgKlen AvgVlen  KbAlen  VbAlen KbWlen% VbWlen% VbUlen% Comps  Kbs  Vbs KblockIDs  / VblockIDs
    k 0,0,0            1   1.03k       0       3       6  33.55m  33.55m     0.1     3.1     0.0     0    1    1 0x102400000 / 0x101400000
    n 0,0,1            1   1.03k       0       3       6  33.55m  33.55m     0.1     3.1     0.0     0    1    1
    #Node pcap% 0 scatter 0 kuniq%  100.0 KbClen%  100.0 VbClen%  100.0 samp    1.0

    H Loc           Dgen    Keys   Tombs AvgKlen AvgVlen  KbAlen  VbAlen KbWlen% VbWlen% VbUlen% Comps  Kbs  Vbs KblockIDs  / VblockIDs
    t 1,0,1            1   1.03k       0       3       6  33.55m  33.55m     0.1     3.1     0.0     0    1    1

    $ cn_kbdump -s /mnt/kvdb/kvdb1/capacity 0x102400000 0x102400000
    0x102400000: K magic 0xfadedfad  ver 5  nkey 1031  ntomb 0
        metrics: keys 1031 tombs 0 key_bytes 4045 val_bytes 6660
        wbt: hdr 112 24  data_pg 1 6  ver 6
        blm: hdr 136 32  data_pg 7 1  ver 5
        pt:  hdr 168 24  data_pg 0 0
        kmd: start_pg 4
        keymin: off 2744 len 2 key 0x6b30
        keymax: off 1392 len 4 key 0x6b393939
        min_seqno: 3
        max_seqno: 3
        blmhdr: magic 0x626c6d68  ver 5  bktsz 64  rotl 11  hashes 8  bitmapsz 4096  modulus 32749
        blm dist    min:   0.131 (67 / 512)
        blm dist    .3%:   0.131 (67 / 512)
        blm dist   2.1%:   0.143 (73 / 512)
        blm dist median:   0.221 (113 / 512)
        blm dist   mean:   0.221 (113 / 512)
        blm dist  97.9%:   0.324 (166 / 512)
        blm dist  99.7%:   0.375 (192 / 512)
        blm dist    max:   0.375 (192 / 512)
        blm bucket size:   64 (512 bits)
        wbthdr: magic 0x4a3a2a1a  ver 6  root 2  leaf1 0  nleaf 2 kmdpgc 3
    ptombs
        wbthdr: magic 0x4a3a2a1a  ver 6  root 0  leaf1 0  nleaf 0 kmdpgc 0


3. Extract mblocks from cn and save in files:

    $ cn_kbdump -w . -s /mnt/kvdb/kvdb1/capacity 0x102400000 0x102400000 / 0x102400000

The following files are created by cn_kbdump:

    K000.0x102400000.gz
    V000.0x101400000.gz

4. Rename and compress with xz:

    gunzip K0*.gz V0*.gz

    mv K000.0x102400000.gz simple_1031c.kbX_wY_bZ
    mv V000.0x101400000.gz simple_1031c.vb1

    xz simple_1031c.kbX_wY_bZ simple_1031c.vb1

  where X, Y, and Z are the kblock, wbt, and bloom header version numbers
  as output by the cn_kbdump command (see sample output in step 2).

4. Inspect files just for fun:

    cn_kbdump -K 30 -V 30  -r simple_1031c.*

5. Create multival kblocks:

    ctxn_validation -i 1000 -k 10  -K1024 -ppc /mnt/kvdb/kvdb1 kvs1
    ctxn_validation -i 2    -k 100 -K1024 -ppc /mnt/kvdb/kvdb1 kvs1
